package http

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math/rand"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

//go:embed all:static
var assets embed.FS

var mu sync.Mutex

func init() {
	functions.HTTP("starter", handler)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/bars.svg" {
		w.Header().Set("Cache-Control", "public")
		w.Header().Add("Cache-Control", "max-age=31536000")
		w.Header().Add("Cache-Control", "immutable")
		w.Header().Set("Content-Type", "image/svg+xml")
		bars, _ := assets.ReadFile("static/bars.svg")
		fmt.Fprint(w, string(bars))
		return
	}

	if r.URL.Path == "/app.css" {
		w.Header().Set("Cache-Control", "public")
		w.Header().Add("Cache-Control", "max-age=31536000")
		w.Header().Add("Cache-Control", "immutable")
		w.Header().Set("Content-Type", "text/css")
		bars, _ := assets.ReadFile("static/app.css")
		fmt.Fprint(w, string(bars))
		return
	}
	ctx := r.Context()

	store := sessions.NewCookieStore(decodeKey(os.Getenv("SESSION_KEY")))

	if r.Header.Get("Accept") == "text/event-stream" && r.URL.Path == "/sse" {
		sse(ctx, store, w, r)
		return
	}

	if r.Method == "POST" {
		post(store, w, r)
		return
	}

	index, _ := assets.ReadFile("static/documents/index.html")

	w.Write(index)
}

func sseInfo(w http.ResponseWriter, msg, detail string) {
	f, _ := assets.ReadFile("static/documents/sseerr.txt")

	t := template.Must(template.New("ss2").Parse(string(f)))

	t.Execute(w, map[string]string{
		"Status": msg,
		"Error":  detail,
	})
	w.(http.Flusher).Flush()
}

func sseError(w http.ResponseWriter, status int, msg string, args ...any) {
	f, _ := assets.ReadFile("static/documents/sseerr.txt")

	t := template.Must(template.New("ss2").Parse(string(f)))

	t.Execute(w, map[string]string{
		"Status": http.StatusText(status),
	})
	w.(http.Flusher).Flush()
	slog.Error(msg, args...)
}

func htmlError(w http.ResponseWriter, status int, msg string, args ...any) {
	w.WriteHeader(status)
	w.Write([]byte(http.StatusText(status)))
	slog.Error(msg, args...)
}

func sse(ctx context.Context, store *sessions.CookieStore, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")

	sess, err := store.Get(r, "session")
	if err != nil {
		sseError(w, http.StatusInternalServerError, "could not obtain session from cookie", "err", err)
		return
	}

	if sess.Values["accessToken"] == nil {
		sseError(w, http.StatusInternalServerError, "Could not obtain access token from cookie", "err", err)
		return
	}

	if _, err := jwt.Parse(sess.Values["accessToken"].(string), func(t *jwt.Token) (any, error) {
		return decodeKey(os.Getenv("SIGNING_KEY")), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})); err != nil {
		sseError(w, http.StatusInternalServerError, "could not decode access token", "err", err)
		return
	}

	IPAddress := r.Header.Get("X-Real-Ip")

	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}

	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}

	parsedIP := netip.MustParseAddr(IPAddress)

	instanceClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		sseError(w, http.StatusInternalServerError, "unable to obtain client for instances", "err", err)
		return
	}

	mu.Lock()
	err = startInstance(ctx, instanceClient)
	mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrInstanceStopping) {
			sseInfo(w, "Instance is currently stopping", "Try again in a few minutes")
			return
		}
		if !errors.Is(err, ErrInstanceNotTerminated) {
			sseError(w, http.StatusInternalServerError, "error starting instance: %v", "err", err)
			return
		}
	}

	addr4, addr6, err := obtainAddr(ctx, instanceClient)
	if err != nil {
		sseError(w, http.StatusInternalServerError, "unable to obtain instance address: %w", "err", err)
		return
	}

	sse1, _ := assets.ReadFile("static/documents/sse1.txt")

	w.Write(sse1)
	w.(http.Flusher).Flush()

	mu.Lock()
	err = updateFirewall(ctx, parsedIP)
	mu.Unlock()
	if err != nil {
		sseError(w, http.StatusInternalServerError, "error updating firewall", "err", err)
		return
	}

	var addr string

	if parsedIP.Is4() {
		addr = addr4
	} else {
		addr = addr6
	}

	sse2, _ := assets.ReadFile("static/documents/sse2.txt")

	template.Must(template.New("sse2").Parse(string(sse2))).Execute(w, map[string]any{"ClientAddr": parsedIP.String(), "ServerAddr": addr})

	ctx.Done()
}

func post(store *sessions.CookieStore, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		htmlError(w, http.StatusBadRequest, "invalid data received", "err", err)
		return
	}

	pass := r.Form.Get("password")

	if err := bcrypt.CompareHashAndPassword([]byte("$2a$12$"+os.Getenv("PASSWORD")), []byte(pass)); err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "wrong password")
		return
	}

	tokExpiration := time.Now().Add(10*time.Minute + time.Duration(rand.Intn(61)-30)*time.Second)

	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(tokExpiration),
		ID:        uuid.NewString(),
	}).SignedString(decodeKey(os.Getenv("SIGNING_KEY")))
	if err != nil {
		htmlError(w, http.StatusInternalServerError, "could not decode access token", "err", err)
		return
	}

	sess, err := store.Get(r, "session")
	if err != nil {
		htmlError(w, http.StatusInternalServerError, "could not obtain session from cookie", "err", err.Error())
		return
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(tokExpiration.Unix() - time.Now().Unix()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	sess.Values["accessToken"] = tok

	if err := sess.Save(r, w); err != nil {
		htmlError(w, http.StatusInternalServerError, "was not able to save cookie session", "err", err.Error())
		return
	}

	ssestart, _ := assets.ReadFile("static/documents/ssestart.html")

	w.Write(ssestart)
}

func decodeKey(encoded string) []byte {
	decoded, _ := base64.RawURLEncoding.DecodeString(encoded)
	return decoded
}

func updateFirewall(ctx context.Context, ip netip.Addr) error {
	var firewallName string

	if ip.Is4() {
		firewallName = os.Getenv("FIREWALL_IP4")
	} else {
		firewallName = os.Getenv("FIREWALL_IP6")
	}

	f, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to create firewall client: %w", err)
	}

	get, err := f.Get(ctx, &computepb.GetFirewallRequest{
		Firewall: firewallName,
		Project:  os.Getenv("PROJECT_NAME"),
	})
	if err != nil {
		return fmt.Errorf("unable to get firewall information: %w", err)
	}

	patch, err := f.Patch(ctx, &computepb.PatchFirewallRequest{
		Firewall: firewallName,
		FirewallResource: &computepb.Firewall{
			SourceRanges: append(get.SourceRanges, ip.String()),
		},
		Project: os.Getenv("PROJECT_NAME"),
	})
	if err != nil {
		return fmt.Errorf("unable to update firewall sources: %w", err)
	}

	if err := patch.Wait(ctx); err != nil {
		return fmt.Errorf("error while waiting for firewall update: %w", err)
	}

	return nil
}

func obtainAddr(ctx context.Context, c *compute.InstancesClient) (string, string, error) {
	ins, err := c.Get(ctx, &computepb.GetInstanceRequest{
		Instance: os.Getenv("INSTANCE_NAME"),
		Project:  os.Getenv("PROJECT_NAME"),
		Zone:     os.Getenv("ZONE"),
	})
	if err != nil {
		return "", "", fmt.Errorf("unable to get information about the instance: %w", err)
	}

	if ins == nil {
		return "", "", errors.New("Could not obtain instance information. InstancesClient.Get resulted in <nil>")
	}

	if len(ins.NetworkInterfaces) < 1 {
		return "", "", errors.New("Instance has no network interfaces")
	}

	if len(ins.NetworkInterfaces[0].AccessConfigs) < 1 {
		return "", "", errors.New("The default network interface of the instance has no 'AccessConfigs' struct")
	}

	addr4, err := netip.ParseAddr(ins.NetworkInterfaces[0].AccessConfigs[0].GetNatIP())
	if err != nil {
		return "", "", err
	}

	addr6, err := netip.ParseAddr(ins.NetworkInterfaces[0].Ipv6AccessConfigs[0].GetExternalIpv6())
	if err != nil {
		return "", "", err
	}

	return addr4.String(), addr6.String(), nil
}

var ErrInstanceNotTerminated = errors.New("instance is not terminated")
var ErrInstanceStopping = errors.New("instance is currently stopping")

func startInstance(ctx context.Context, c *compute.InstancesClient) error {
	ins, err := c.Get(ctx, &computepb.GetInstanceRequest{
		Instance: os.Getenv("INSTANCE_NAME"),
		Project:  os.Getenv("PROJECT_NAME"),
		Zone:     os.Getenv("ZONE"),
	})
	if err != nil {
		return fmt.Errorf("unable to get information about the instance: %w", err)
	}

	if ins == nil {
		return errors.New("Could not obtain instance information. InstancesClient.Get resulted in <nil>")
	}

	if ins.Status == nil {
		return errors.New("unable to obtain instance status. Status field is <nil>")
	}

	if *ins.Status == "STOPPING" || *ins.Status == "SUSPENDING" || *ins.Status == "REPAIRING" {
		slog.Info("Instance is stopping", "status", *ins.Status)
		return ErrInstanceStopping
	}

	if *ins.Status != "TERMINATED" {
		slog.Info("Instance is already running or starting up", "status", *ins.Status)
		return ErrInstanceNotTerminated
	}

	op, err := c.Start(ctx, &computepb.StartInstanceRequest{
		Instance: os.Getenv("INSTANCE_NAME"),
		Project:  os.Getenv("PROJECT_NAME"),
		Zone:     os.Getenv("ZONE"),
	})
	if err != nil {
		return fmt.Errorf("unable to start instance: %w", err)
	}

	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("error while waiting for instance to start: %w", err)
	}

	return nil
}
