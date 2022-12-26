build:
	go build cmd/server/server.go
	go build cmd/client/client.go
tests:
	go test pkg/vulners_test.go

lint:
	go vet pkg/netvuln.go
	go vet pkg/vulners.go
	go vet cmd/client/client.go
	go vet cmd/server/server.go
run server:
	go run cmd/server/server.go
run client:
	go run cmd/client/client.go
