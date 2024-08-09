default:

linux-amd64: *.go
	GOOS=linux GOARCH=amd64 go build -o bin/dnsmuxer-$@ .

linux-arm64: *.go
	GOOS=linux GOARCH=arm64 go build -o bin/dnsmuxer-$@ .

darwin-amd64: *.go
	GOOS=darwin GOARCH=amd64 go build -o bin/dnsmuxer-$@ .

clean:
	rm -rf bin
