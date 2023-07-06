webhook-go: go.mod $(wildcard *.go)
	CGO_ENABLED=0 go build -ldflags='-s -w'
