.PHONY: backend test

backend:
	cd backend && go run ./cmd/sentracore

test:
	cd backend && go test ./...
