package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// DNSQuery represents a DNS query from client.
type DNSQuery struct {
	srcAddr net.Addr
	payload []byte
	domain  string
	cn      bool
	repr    string
}

func NewDNSQuery(srcAddr net.Addr, payload []byte) (query *DNSQuery, err error) {
	query = &DNSQuery{
		srcAddr: srcAddr,
		payload: payload,
	}
	if err = query.parsePayload(); err != nil {
		return
	}
	query.cn = queryCN(query.domain)
	log.Debug("new query:", query)
	return
}

func (q *DNSQuery) LogDone(err error) {
	if err == nil {
		log.Info(q)
	} else {
		log.Error(q, "--", err)
	}
}

func (q *DNSQuery) String() string {
	var cn string
	if q.domain != "" {
		if q.cn {
			cn = "1"
		} else {
			cn = "0"
		}
	}
	return fmt.Sprintf("SRC=%s/%s SIZE=%d %s CN=%s",
		q.srcAddr.String(), q.srcAddr.Network(), len(q.payload), q.repr, cn)
}

// parsePayload parses the payload for its header and the domain in the first question.
// Refer: https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
func (q *DNSQuery) parsePayload() error {
	buf := q.payload
	if len(buf) < 12 {
		return errors.New("query too short")
	}

	// Read header
	id := buf[0:2]
	flags := buf[2:4]
	numQuestions := binary.BigEndian.Uint16(buf[4:6])
	numAnswers := binary.BigEndian.Uint16(buf[6:8])
	numAuthorityRRs := binary.BigEndian.Uint16(buf[8:10])
	numAdditionalRRs := binary.BigEndian.Uint16(buf[10:12])

	if numQuestions == 0 {
		q.repr = fmt.Sprintf("ID=0x%02x%02x FLAG=0x%02x%02x NUMS=%d,%d,%d,%d NOQUESTION",
			id[0], id[1], flags[0], flags[1],
			numQuestions, numAnswers, numAuthorityRRs, numAdditionalRRs)
		return nil
	}

	// Read the first question
	buf = buf[12:]
	subds := []string{}
	for buf[0] > 0 {
		n := int(buf[0])
		subds = append(subds, string(buf[1:1+n]))
		buf = buf[1+n:]
	}
	buf = buf[1:]
	domain := strings.Join(subds, ".")
	recType := binary.BigEndian.Uint16(buf[0:2])
	// class := binary.BigEndian.Uint16(buf[2:4])

	q.domain = domain
	q.repr = fmt.Sprintf("ID=0x%02x%02x FLAG=0x%02x%02x NUMS=%d,%d,%d,%d DOMAIN=%s TYPE=%s",
		id[0], id[1], flags[0], flags[1],
		numQuestions, numAnswers, numAuthorityRRs, numAdditionalRRs,
		domain, recType2Str(int(recType)))
	return nil
}
