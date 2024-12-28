package main

import (
	"fmt"
	"net"
)

func forwardUDPQuery(payload []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, udpFwdAddr)
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

func handleUDPQuery(srcAddr net.Addr, payload []byte) {
	query, err := NewDNSQuery(srcAddr, payload)
	if err != nil {
		query.LogDone(err)
		return
	}

	// Forward to local server
	if query.cn {
		reply, err := forwardUDPQuery(query.payload)
		if err != nil {
			query.LogDone(err)
			return
		}
		udpReplyChan <- udpReply{reply, query.srcAddr}
		query.LogDone(nil)
		return
	}

	// Forward to DoT server
	callback := func(payload []byte, err error) {
		if err != nil {
			query.LogDone(err)
			return
		}
		// Truncate the payload and add the TC flag if it exceeds 512 bytes
		if len(payload) > 512 {
			err = fmt.Errorf("truncated: %d", len(payload))
			payload = payload[:512]
			payload[2] |= 0x2
		}
		udpReplyChan <- udpReply{payload, query.srcAddr}
		query.LogDone(err)
	}
	makeDoTQuery(query.payload, callback)
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
			go handleUDPQuery(addr, buf[:n])
		}
	}()

	// Send replies
	go func() {
		for reply := range udpReplyChan {
			server.WriteTo(reply.payload, reply.addr)
		}
	}()
}
