package main

import (
	"encoding/binary"
	"io"
	"net"
)

func readTCPMessage(conn net.Conn) ([]byte, error) {
	// read size
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(buf)

	// read payload
	payload := make([]byte, size)
	copy(payload, buf)
	n, err := io.ReadFull(conn, payload)
	if err != nil {
		return payload[:n], err
	}

	return payload, nil
}

func writeTCPMessage(conn net.Conn, payload []byte) error {
	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, uint16(len(payload)))
	if _, err := conn.Write(size); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return nil
}

func forwardTCPQuery(payload []byte) ([]byte, error) {
	conn, err := net.Dial("tcp", *flagFwdLocal)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := writeTCPMessage(conn, payload); err != nil {
		return nil, err
	}

	reply, err := readTCPMessage(conn)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func handleTCPClient(conn net.Conn) {
	defer conn.Close()

	payload, err := readTCPMessage(conn)
	query := &DNSQuery{
		payload: payload,
		srcAddr: conn.RemoteAddr(),
	}
	if err != nil {
		query.done(err)
		return
	}
	query.domain, err = parseDNSDomain(payload)
	if err != nil {
		query.done(err)
		return
	}

	// Forward query
	query.cn = queryCN(query.domain)
	var reply []byte
	if query.cn {
		reply, err = forwardTCPQuery(query.payload)
	} else {
		done := make(chan bool)
		makeDoTQuery(payload, func(b []byte, e error) {
			reply = b
			err = e
			done <- true
		})
		<-done
	}
	if err != nil {
		query.done(err)
		return
	}

	// Send reply
	if err := writeTCPMessage(conn, reply); err != nil {
		query.done(err)
		return
	}
	query.done(nil)
}

func startTCPListener(address string) {
	server, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	log.Warn("listen on tcp", address)

	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go handleTCPClient(conn)
		}
	}()
}
