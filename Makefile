run:
	@go run cmd/main.go
deploy:
	@gcloud functions deploy vs-starter
