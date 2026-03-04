package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

// readerConn wraps a net.Conn so that Read comes from a custom reader
// (e.g. a MultiReader that replays peeked bytes before the live conn).
type readerConn struct {
	net.Conn
	reader io.Reader
}

func (c *readerConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// PeekSNI reads the beginning of conn to extract the SNI from a TLS
// ClientHello without terminating TLS. It returns the SNI (empty if not
// TLS or no SNI extension), and an io.Reader that replays the peeked
// bytes followed by the remainder of conn.
// Even on error the returned reader is always valid.
func PeekSNI(conn net.Conn) (string, io.Reader, error) {
	buf := make([]byte, 16384)
	n, err := conn.Read(buf)
	if n == 0 {
		return "", io.MultiReader(bytes.NewReader(buf[:0]), conn), err
	}
	buf = buf[:n]
	sni := parseSNI(buf)
	return sni, io.MultiReader(bytes.NewReader(buf), conn), nil
}

// parseSNI extracts the SNI hostname from raw TLS ClientHello bytes.
// Returns "" for any parse failure (non-TLS, truncated, missing SNI).
func parseSNI(data []byte) string {
	// Need at least 5 bytes for the TLS record header.
	if len(data) < 5 {
		return ""
	}

	// Content type must be Handshake (0x16).
	if data[0] != 0x16 {
		return ""
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	payload := data[5:]
	if len(payload) < recordLen {
		payload = payload[:len(payload)] // use what we have
	} else {
		payload = payload[:recordLen]
	}

	// Handshake type must be ClientHello (0x01), need 4 bytes for header.
	if len(payload) < 4 || payload[0] != 0x01 {
		return ""
	}

	// Handshake length (3 bytes).
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	payload = payload[4:]
	if len(payload) < hsLen {
		// truncated but continue with what we have
	}

	// ClientHello body: version(2) + random(32) = 34 bytes minimum.
	if len(payload) < 34 {
		return ""
	}
	pos := 2 + 32 // skip version + random

	// Session ID (1 byte length + variable).
	if pos >= len(payload) {
		return ""
	}
	sidLen := int(payload[pos])
	pos++
	pos += sidLen
	if pos+2 > len(payload) {
		return ""
	}

	// Cipher suites (2 byte length + variable).
	csLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(payload) {
		return ""
	}

	// Compression methods (1 byte length + variable).
	compLen := int(payload[pos])
	pos++
	pos += compLen
	if pos+2 > len(payload) {
		return ""
	}

	// Extensions (2 byte length + variable).
	extLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}

	// Iterate extensions looking for SNI (type 0x0000).
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		eLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4
		if pos+eLen > extEnd {
			break
		}
		if extType == 0x0000 {
			return parseSNIExtension(payload[pos : pos+eLen])
		}
		pos += eLen
	}

	return ""
}

// parseSNIExtension parses the payload of an SNI extension to find a
// host_name entry (type 0x00).
func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < listLen {
		listLen = len(data)
	}
	off := 0
	for off+3 <= listLen {
		nameType := data[off]
		nameLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		off += 3
		if off+nameLen > listLen {
			break
		}
		if nameType == 0x00 {
			return string(data[off : off+nameLen])
		}
		off += nameLen
	}
	return ""
}
