run:
	FUNCTION_TARGET=Handler LOCAL_ONLY=true go run cmd/main.go
deploy:	
	gcloud functions deploy vs-starter