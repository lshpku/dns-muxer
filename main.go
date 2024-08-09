package main

import (
	"flag"
	"net"
)

var (
	flagListen    = flag.String("listen", "", "serve DNS at this address")
	flagListenUDP = flag.String("listen-udp", "", "serve DNS at this address (for UDP)")
	flagListenTCP = flag.String("listen-tcp", "", "serve DNS at this address (for TCP)")
	flagQueryCN   = flag.String("query-cn", "", "query CN at this address")
	flagFwd       = flag.String("forward", "", "local DNS address")
	flagFwdUDP    = flag.String("forward-udp", "", "local DNS address (for UDP)")
	flagFwdTCP    = flag.String("forward-tcp", "", "local DNS address (for TCP)")
	flagFwdProxy  = flag.String("forward-proxy", "", "DoT proxy address")

	udpFwdAddr *net.UDPAddr
	tcpFwdAddr *net.TCPAddr
)

func main() {
	flag.Parse()

	chooseFirstAvail := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}

	var err error
	udpAddr := chooseFirstAvail(*flagListenUDP, *flagListen)
	if udpAddr != "" {
		if fwdAddr := chooseFirstAvail(*flagFwdUDP, *flagFwd); fwdAddr != "" {
			if udpFwdAddr, err = net.ResolveUDPAddr("udp", fwdAddr); err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal("UDP forward address is not specified")
		}
	}
	tcpAddr := chooseFirstAvail(*flagListenTCP, *flagListen)
	if tcpAddr != "" {
		if fwdAddr := chooseFirstAvail(*flagFwdTCP, *flagFwd); fwdAddr != "" {
			if tcpFwdAddr, err = net.ResolveTCPAddr("tcp", fwdAddr); err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal("TCP forward address is not specified")
		}
	}
	if udpAddr == "" && tcpAddr == "" {
		log.Fatal("No listener is specified")
	}

	if udpAddr != "" {
		startUDPListener(udpAddr)
	}
	if tcpAddr != "" {
		startTCPListener(tcpAddr)
	}

	go runDoTClient()

	select {}
}
