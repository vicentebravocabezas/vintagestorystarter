package http

import (
	"context"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"net/netip"
	"os"
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

func sse(ctx context.Context, store *sessions.CookieStore, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")

	sess, err := store.Get(r, "session")
	if err != nil {
		log.Fatal(err)
	}

	if sess.Values["accessToken"] == nil {
		log.Fatal(err)
	}

	if _, err := jwt.Parse(sess.Values["accessToken"].(string), func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return decodeKey(os.Getenv("SIGNING_KEY")), nil
	}); err != nil {
		log.Fatal(err)
	}

	IPAddress := r.Header.Get("X-Real-Ip")

	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}

	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}

	parsedIP := netip.MustParseAddr(IPAddress)

	addr4, addr6, err := startInstance(ctx)
	if err != nil {
		log.Fatalf("error starting instance: %v", err)
	}

	sse1, _ := assets.ReadFile("static/documents/sse1.html")

	w.Write(sse1)
	w.(http.Flusher).Flush()

	if err := updateFirewall(ctx, parsedIP); err != nil {
		log.Fatalf("error updating firewall: %v", err)
	}

	var addr string

	if parsedIP.Is4() {
		addr = addr4
	} else {
		addr = addr6
	}

	sse2, _ := assets.ReadFile("static/documents/sse2.html")

	template.Must(template.New("sse2").Parse(string(sse2))).Execute(w, map[string]any{"ClientAddr": parsedIP.String(), "ServerAddr": addr})

	ctx.Done()
}

func post(store *sessions.CookieStore, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Fatalf("error parsing form: %v", err)
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
		log.Fatal(err)
	}

	sess, err := store.Get(r, "session")
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
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
		return err
	}

	get, err := f.Get(ctx, &computepb.GetFirewallRequest{
		Firewall: firewallName,
		Project:  os.Getenv("PROJECT_NAME"),
	})
	if err != nil {
		return err
	}

	patch, err := f.Patch(ctx, &computepb.PatchFirewallRequest{
		Firewall: firewallName,
		FirewallResource: &computepb.Firewall{
			SourceRanges: append(get.SourceRanges, ip.String()),
		},
		Project: os.Getenv("PROJECT_NAME"),
	})
	if err != nil {
		return err
	}

	if err := patch.Wait(ctx); err != nil {
		return err
	}

	if !patch.Done() {
		panic("operation failed")
	}

	return nil
}

func startInstance(ctx context.Context) (string, string, error) {
	c, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return "", "", err
	}

	ins1, err := c.Get(ctx, &computepb.GetInstanceRequest{
		Instance: os.Getenv("INSTANCE_NAME"),
		Project:  os.Getenv("PROJECT_NAME"),
		Zone:     os.Getenv("ZONE"),
	})
	if err != nil {
		return "", "", err
	}

	if *ins1.Status == "TERMINATED" {
		op, err := c.Start(ctx, &computepb.StartInstanceRequest{
			Instance: os.Getenv("INSTANCE_NAME"),
			Project:  os.Getenv("PROJECT_NAME"),
			Zone:     os.Getenv("ZONE"),
		})
		if err != nil {
			return "", "", err
		}

		if err := op.Wait(ctx); err != nil {
			return "", "", err
		}
	}

	ins2, err := c.Get(ctx, &computepb.GetInstanceRequest{
		Instance: os.Getenv("INSTANCE_NAME"),
		Project:  os.Getenv("PROJECT_NAME"),
		Zone:     os.Getenv("ZONE"),
	})
	if err != nil {
		return "", "", err
	}

	addr4 := netip.MustParseAddr(ins2.NetworkInterfaces[0].AccessConfigs[0].GetNatIP()).String()

	addr6 := netip.MustParseAddr(ins2.NetworkInterfaces[0].Ipv6AccessConfigs[0].GetExternalIpv6()).String()

	return addr4, addr6, nil
}
