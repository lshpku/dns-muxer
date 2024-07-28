all: dns_muxer

dns_muxer: *.go
	go build -o $@ .

clean:
	rm -f dns_muxer
