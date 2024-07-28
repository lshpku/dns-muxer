package main

import (
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
)

// DoTQuery represents a query that is sent to the DoT server.
type DoTQuery struct {
	payload  []byte
	callback func([]byte, error)
	retry    int
}

var DoTChan = make(chan *DoTQuery, 16)

func makeDoTQuery(payload []byte, callback func([]byte, error)) {
	DoTChan <- &DoTQuery{
		payload:  payload,
		callback: callback,
		retry:    3,
	}
}

type DoTClient struct {
	conn *tls.Conn
	// Queries that are sent and haven't been replied.
	// Note: it can only be closed from the writer side.
	queries chan *DoTQuery
	closed  atomic.Bool
}

func (c *DoTClient) runReader() {
	var err error

	// Read replies and callback on queries
	for {
		var payload []byte
		payload, err = readTCPMessage(c.conn)
		if err != nil {
			break
		}

		if query := <-c.queries; query != nil {
			go query.callback(payload, nil)
		} else {
			err = errors.New("DoT reply has no matching query")
			break
		}
	}

	if !c.closed.Swap(true) {
		log.Info("DoT reader closed:", err)
	}
	c.conn.Close()

	// Retry unfinished queries
	for query := range c.queries {
		retryQuery(query)
	}
}

func newDoTClient() (*DoTClient, error) {
	// Dial socks proxy
	rawConn, err := net.Dial("tcp", *flagFwdProxy)
	if err != nil {
		return nil, err
	}
	if err := socks5Handshake(rawConn, "dns.google", 853); err != nil {
		rawConn.Close()
		return nil, err
	}

	// Do TLS handshake
	conn := tls.Client(rawConn, &tls.Config{
		ServerName: "dns.google",
	})
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	client := &DoTClient{
		conn:    conn,
		queries: make(chan *DoTQuery, 8),
	}
	go client.runReader()

	log.Info("new DoT client")
	return client, nil
}

func retryQuery(query *DoTQuery) {
	query.retry--
	if query.retry <= 0 {
		query.callback(nil, errors.New("Max retries exceeded"))
		return
	}
	select {
	case DoTChan <- query:
		log.Info("retry DoT query")
	default:
		query.callback(nil, errors.New("DoT channel is full"))
	}
}

func runDoTClient() {
	var client *DoTClient

	for query := range DoTChan {
		log.Debug("handling query", len(query.payload))

		// Create a client if there is no client, or if the current client has
		// been closed.
		if client == nil || client.closed.Load() {
			if client != nil {
				close(client.queries)
			}
			var err error
			client, err = newDoTClient()
			if err != nil {
				retryQuery(query)
				continue
			}
		}

		// Try to forward the query.
		// Close the client if Write fails.
		if err := writeTCPMessage(client.conn, query.payload); err == nil {
			log.Debug("sending query", len(query.payload))
			client.queries <- query
		} else {
			if !client.closed.Swap(true) {
				log.Info("DoT writer closed:", err)
			}
			client.conn.Close()
			retryQuery(query)
		}
	}
}
