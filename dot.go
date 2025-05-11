package main

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DoTQuery represents a query that is sent to the DoT server.
type DoTQuery struct {
	*DNSQuery
	callback func([]byte, error)
	retry    int
	deadline time.Time
}

var DoTChan = make(chan *DoTQuery, 16)

func makeDoTQuery(query *DNSQuery, callback func([]byte, error)) {
	DoTChan <- &DoTQuery{
		DNSQuery: query,
		callback: callback,
		retry:    3,
	}
}

type DoTClient struct {
	conn *tls.Conn

	// Queries that are sent and haven't been replied.
	// Note: it can only be closed from the writer side.
	queries chan *DoTQuery

	// The latest query in the queries chan.
	// Note: the writer should set latestQuery before writing the chan,
	// and the opposite for the reader.
	latestQuery *DoTQuery
	latestMutex sync.Mutex

	closed atomic.Bool
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

		query := <-c.queries
		if query == nil {
			err = errors.New("DoT reply has no matching query")
			break
		}

		// Update timeout
		var isLastestQuery bool
		c.latestMutex.Lock()
		if query == c.latestQuery {
			c.conn.SetReadDeadline(time.Time{})
			isLastestQuery = true
		}
		c.latestMutex.Unlock()

		log.Debugf("DoT reader replied: %s latest=%t", query, isLastestQuery)
		go query.callback(payload, nil)
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

	log.Info("new DoT client created")
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
		// Create a client if there is no client, or if the current client has
		// been closed.
		var isFirstQuery bool
		if client == nil || client.closed.Load() {
			if client != nil {
				close(client.queries)
			}
			var err error
			client, err = newDoTClient()
			if err != nil {
				log.Error("failed to create DoT client:", err)
				retryQuery(query)
				continue
			}
			isFirstQuery = true
		}

		// Set deadline for the query.
		client.latestMutex.Lock()
		timeout := time.Second * 2
		if isFirstQuery {
			timeout = time.Second * 5 // give more time for the first query
		}
		query.deadline = time.Now().Add(timeout)
		client.conn.SetReadDeadline(query.deadline)
		client.latestQuery = query
		client.latestMutex.Unlock()

		// Try to forward the query.
		// Close the client if Write fails.
		if err := writeTCPMessage(client.conn, query.payload); err == nil {
			log.Debugf("sent DoT query: %s timeout=%s", query, timeout)
			client.queries <- query
		} else {
			log.Debug("failed to send DoT query:", query)
			if !client.closed.Swap(true) {
				log.Info("DoT writer closed:", err)
			}
			client.conn.Close()
			retryQuery(query)
		}
	}
}
