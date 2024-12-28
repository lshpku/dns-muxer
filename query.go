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

	// header
	id               [2]byte
	flags            [2]byte
	numQuestions     uint16
	numAnswers       uint16
	numAuthorityRRs  uint16
	numAdditionalRRs uint16

	// the first question
	domain  string
	recType uint16
	class   uint16

	cn bool
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
	log.Debug("new query:", query.Repr())
	return
}

func (q *DNSQuery) LogDone(err error) {
	if err == nil {
		log.Info(q.Repr())
	} else {
		log.Error(q.Repr(), "--", err)
	}
}

func (q *DNSQuery) String() string {
	return fmt.Sprintf("%s/%s@%02x%02x",
		q.srcAddr.String(), q.srcAddr.Network(), q.id[0], q.id[1])
}

func (q *DNSQuery) Repr() string {
	return fmt.Sprintf(
		"SRC=%s/%s ID=0x%02x%02x FLAG=0x%02x%02x NUMS=%d,%d,%d,%d DOMAIN=%s TYPE=%s SIZE=%d CN=%d",
		q.srcAddr.String(), q.srcAddr.Network(),
		q.id[0], q.id[1], q.flags[0], q.flags[1],
		q.numQuestions, q.numAnswers, q.numAuthorityRRs, q.numAdditionalRRs,
		q.domain, recType2Str(int(q.recType)), len(q.payload), boolToInt(q.cn))
}

// parsePayload parses the payload for its header and the domain in the first question.
// Refer: https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
func (q *DNSQuery) parsePayload() error {
	buf := q.payload
	if len(buf) < 12 {
		return errors.New("query too short")
	}

	// Read header
	copy(q.id[:], buf[0:2])
	copy(q.flags[:], buf[2:4])
	q.numQuestions = binary.BigEndian.Uint16(buf[4:6])
	q.numAnswers = binary.BigEndian.Uint16(buf[6:8])
	q.numAuthorityRRs = binary.BigEndian.Uint16(buf[8:10])
	q.numAdditionalRRs = binary.BigEndian.Uint16(buf[10:12])

	// Read the first question
	buf = buf[12:]
	subds := []string{}
	for buf[0] > 0 {
		n := int(buf[0])
		subds = append(subds, string(buf[1:1+n]))
		buf = buf[1+n:]
	}
	buf = buf[1:]
	q.domain = strings.Join(subds, ".")
	q.recType = binary.BigEndian.Uint16(buf[0:2])
	q.class = binary.BigEndian.Uint16(buf[2:4])

	return nil
}
