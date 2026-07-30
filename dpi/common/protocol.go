package common

import (
	"encoding/binary"
	"io"
)

const (
	// MaxChunkSize is the maximum size of a single encrypted chunk.
	// Larger uploads use streaming; smaller use POST.
	MaxChunkSize = 64 * 1024 // 64KB - threshold for POST vs streaming

	// Protocol version
	Version = 1
)

// Message types
const (
	MsgConnect   = 0x01
	MsgData      = 0x02
	MsgClose     = 0x03
	MsgUDPAssoc  = 0x04
	MsgUDPPacket = 0x05
)

// StreamHeader precedes each encrypted payload.
type StreamHeader struct {
	Version    uint8
	MsgType    uint8
	ConnID     uint32
	PayloadLen uint32
}

const StreamHeaderSize = 10

// WriteStreamHeader writes a stream header.
func WriteStreamHeader(w io.Writer, msgType uint8, connID uint32, payloadLen uint32) error {
	h := make([]byte, StreamHeaderSize)
	h[0] = Version
	h[1] = msgType
	binary.BigEndian.PutUint32(h[2:6], connID)
	binary.BigEndian.PutUint32(h[6:10], payloadLen)
	_, err := w.Write(h)
	return err
}

// ReadStreamHeader reads a stream header.
func ReadStreamHeader(r io.Reader) (StreamHeader, error) {
	var h StreamHeader
	buf := make([]byte, StreamHeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return h, err
	}
	h.Version = buf[0]
	h.MsgType = buf[1]
	h.ConnID = binary.BigEndian.Uint32(buf[2:6])
	h.PayloadLen = binary.BigEndian.Uint32(buf[6:10])
	return h, nil
}

// ConnectRequest is sent when opening a new connection.
type ConnectRequest struct {
	Network string // "tcp" or "udp"
	Address string // "host:port"
}
