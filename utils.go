package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	syslog "log"
	"net"
	"os"
	"strings"
)

type Logger struct{}

func (l *Logger) Debugf(fmt string, a ...any) {}
func (l *Logger) Infof(fmt string, a ...any)  { syslog.Printf("[INFO] "+fmt, a...) }
func (l *Logger) Warnf(fmt string, a ...any)  { syslog.Printf("[WARN] "+fmt, a...) }
func (l *Logger) Errorf(fmt string, a ...any) { syslog.Printf("[ERRO] "+fmt, a...) }
func (l *Logger) Fatalf(fmt string, a ...any) { syslog.Printf("[FATA] "+fmt, a...); os.Exit(1) }

func (l *Logger) Debug(a ...any) {}
func (l *Logger) Info(a ...any)  { syslog.Println(append([]any{"[INFO]"}, a...)...) }
func (l *Logger) Warn(a ...any)  { syslog.Println(append([]any{"[WARN]"}, a...)...) }
func (l *Logger) Error(a ...any) { syslog.Println(append([]any{"[ERRO]"}, a...)...) }
func (l *Logger) Fatal(a ...any) { syslog.Println(append([]any{"[FATA]"}, a...)...); os.Exit(1) }

var log = Logger{}

// parseDNSDomain parses the DNS message for its domain.
// Refer: https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
func parseDNSDomain(buf []byte) (string, error) {
	if len(buf) < 12 {
		return "", errors.New("query too short")
	}
	id := buf[0:2]
	flags := buf[2:4]
	numQuestions := binary.BigEndian.Uint16(buf[4:6])
	numAnswers := binary.BigEndian.Uint16(buf[6:8])
	numAuthorityRRs := binary.BigEndian.Uint16(buf[8:10])
	numAdditionalRRs := binary.BigEndian.Uint16(buf[10:12])

	i := 12
	for q := 0; q < int(numQuestions); q++ {
		subds := make([]string, 0)
		for buf[i] > 0 {
			n := int(buf[i])
			subds = append(subds, string(buf[i+1:i+1+n]))
			i += n + 1
		}
		i++
		domain := strings.Join(subds, ".")
		qtype := binary.BigEndian.Uint16(buf[i : i+2])
		class := binary.BigEndian.Uint16(buf[i+2 : i+4])
		i += 4

		if numAnswers > 0 || numAuthorityRRs > 0 || numAdditionalRRs > 0 {
			idStr := fmt.Sprintf("0x%02x%02x", id[0], id[1])
			flagStr := fmt.Sprintf("0x%02x%02x", flags[0], flags[1])
			log.Debugf("ID=%s FLAGS=%s NUMS=%d,%d,%d,%d DOMAIN=%s TYPE=%d CLASS=%d",
				idStr, flagStr, numQuestions, numAnswers, numAuthorityRRs, numAdditionalRRs,
				domain, qtype, class)
		}
		return domain, nil
	}

	return "", errors.New("no question")
}

func socks5Handshake(conn net.Conn, address string, port int) error {
	data := []byte("\x05\x01\x00\x05\x01\x00\x03")
	data = append(data, byte(len(address)))
	data = append(data, []byte(address)...)
	off := len(data)
	data = append(data, 0, 0)
	binary.BigEndian.PutUint16(data[off:], uint16(port))

	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("socks: %s", err)
	}

	buf := make([]byte, 12)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("socks: %s", err)
	}

	res := []byte("\x05\x00\x05\x00\x00")
	if !bytes.Equal(res, buf[:len(res)]) {
		return errors.New("socks: bad response")
	}
	return nil
}

// queryCN queries whether it is a CN domain.
func queryCN(domain string) bool {
	conn, err := net.Dial("tcp", *flagQueryCN)
	if err != nil {
		log.Error("query cn:", err)
		return true
	}
	defer conn.Close()

	// Make a socks5 connection with domain as its destination
	data := []byte("\x05\x01\x00\x05\x01\x00\x03")
	data = append(data, byte(len(domain)))
	data = append(data, []byte(domain)...)
	data = append(data, 0, 80, 0)

	if _, err := conn.Write(data); err != nil {
		log.Error("query cn:", err)
		return true
	}

	// Socks returns 12 bytes for CN and >12 bytes for non-CN
	buf := make([]byte, 13)
	if _, err = io.ReadFull(conn, buf); err == nil {
		return false
	}

	return true
}
