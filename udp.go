package main

import "net"

// DNSQuery represents a DNS query from client.
type DNSQuery struct {
	srcAddr net.Addr
	payload []byte
	domain  string
	cn      bool
	flacTC  bool
}

func (q *DNSQuery) done(err error) {
	var cn string
	if q.domain != "" {
		if q.cn {
			cn = "1"
		} else {
			cn = "0"
		}
	}
	if err == nil {
		log.Infof("SRC=%s/%s SIZE=%d DOMAIN=%s CN=%s",
			q.srcAddr.String(), q.srcAddr.Network(), len(q.payload), q.domain, cn)
	} else {
		log.Errorf("SRC=%s/%s SIZE=%d DOMAIN=%s CN=%s %s",
			q.srcAddr.String(), q.srcAddr.Network(), len(q.payload), q.domain, cn, err)
	}
}

var udpFwdAddr *net.UDPAddr

func forwardUDPQuery(payload []byte) ([]byte, error) {
	fwdAddr, err := net.ResolveUDPAddr("udp", *flagFwdLocal)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP("udp", nil, fwdAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

type udpReply struct {
	payload []byte
	addr    net.Addr
}

var udpReplyChan = make(chan udpReply)

func handleUDPQuery(query *DNSQuery) {
	var err error
	query.domain, err = parseDNSDomain(query.payload)
	if err != nil {
		query.done(err)
		return
	}

	// Forward to local server
	query.cn = queryCN(query.domain)
	if query.cn {
		reply, err := forwardUDPQuery(query.payload)
		if err != nil {
			query.done(err)
			return
		}
		udpReplyChan <- udpReply{reply, query.srcAddr}
		query.done(nil)
		return
	}

	// Forward to DoT server
	callback := func(payload []byte, err error) {
		if err != nil {
			query.done(err)
			return
		}
		// Truncate the payload and add the TC flag if it exceeds 512 bytes
		if len(payload) > 512 {
			payload = payload[:512]
			payload[2] |= 0x2
			query.flacTC = true
		}
		udpReplyChan <- udpReply{payload, query.srcAddr}
		query.done(nil)
	}
	DoTChan <- &DoTQuery{query.payload, callback, 3}
}

func startUDPListener(address string) {
	server, err := net.ListenPacket("udp", address)
	if err != nil {
		log.Fatal(err)
	}
	log.Warn("listen on udp", address)

	// Serve queries
	go func() {
		for {
			buf := make([]byte, 512)
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				log.Fatal(err)
			}
			go handleUDPQuery(&DNSQuery{
				payload: buf[:n],
				srcAddr: addr,
			})
		}
	}()

	// Send replies
	go func() {
		for reply := range udpReplyChan {
			server.WriteTo(reply.payload, reply.addr)
		}
	}()
}
