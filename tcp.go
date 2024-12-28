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
	n, err := io.ReadFull(conn, payload)
	if err != nil {
		return payload[:n], err
	}

	return payload, nil
}

func writeTCPMessage(conn net.Conn, payload []byte) error {
	// According to https://www.rfc-editor.org/rfc/rfc7766#section-8, the
	// length field and the message SHOULD be sent at the same time.
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	copy(buf[2:], payload)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	return nil
}

func forwardTCPQuery(payload []byte) ([]byte, error) {
	conn, err := net.DialTCP("tcp", nil, tcpFwdAddr)
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
	query, newErr := NewDNSQuery(conn.RemoteAddr(), payload)
	if err != nil {
		query.LogDone(err)
		return
	}
	if newErr != nil {
		query.LogDone(newErr)
		return
	}

	// Forward query
	var reply []byte
	if query.cn {
		reply, err = forwardTCPQuery(query.payload)
	} else {
		done := make(chan bool)
		makeDoTQuery(query, func(b []byte, e error) {
			reply = b
			err = e
			done <- true
		})
		<-done
	}
	if err != nil {
		query.LogDone(err)
		return
	}

	// Send reply
	if err := writeTCPMessage(conn, reply); err != nil {
		query.LogDone(err)
		return
	}
	query.LogDone(nil)
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
