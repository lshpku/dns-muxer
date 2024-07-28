package main

import (
	"flag"
)

var (
	flagListen    = flag.String("listen", "", "serve DNS at this address")
	flagListenUDP = flag.String("listen-udp", "", "serve DNS at this address (for UDP)")
	flagListenTCP = flag.String("listen-tcp", "", "serve DNS at this address (for TCP)")
	flagQueryCN   = flag.String("query-cn", "", "query CN at this address")
	flagFwdLocal  = flag.String("forward-local", "", "local DNS address")
	flagFwdProxy  = flag.String("forward-proxy", "", "DoT proxy address")
)

func main() {
	flag.Parse()

	chooseFirstAvail := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}

	hasListener := false
	if addr := chooseFirstAvail(*flagListenUDP, *flagListen); addr != "" {
		startUDPListener(addr)
		hasListener = true
	}
	if addr := chooseFirstAvail(*flagListenTCP, *flagListen); addr != "" {
		startTCPListener(addr)
		hasListener = true
	}
	if !hasListener {
		log.Fatal("No listener is specified")
	}

	go runDoTClient()

	select {}
}
