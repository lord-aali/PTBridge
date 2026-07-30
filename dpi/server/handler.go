package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lord-aali/PTBridge.git/dpi/common"
)

const dialTimeout = 30 * time.Second

type tunnelHandler struct {
	server *Server
}

func newTunnelHandler(s *Server) *tunnelHandler {
	return &tunnelHandler{server: s}
}

// handleTunnel handles POST (form-like) and streaming uploads.
func (h *tunnelHandler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Realistic headers for response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", 400)
		return
	}
	r.Body.Close()

	if len(body) == 0 {
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	decrypted, err := h.server.encryptor.DecryptStream(body)
	if err != nil {
		log.Printf("[Server] Decrypt error: %v", err)
		http.Error(w, "Bad Request", 400)
		return
	}

	if len(decrypted) < common.StreamHeaderSize {
		http.Error(w, "Bad Request", 400)
		return
	}

	hdr := common.StreamHeader{
		Version:    decrypted[0],
		MsgType:    decrypted[1],
		ConnID:     binary.BigEndian.Uint32(decrypted[2:6]),
		PayloadLen: binary.BigEndian.Uint32(decrypted[6:10]),
	}
	payload := decrypted[10:]

	switch hdr.MsgType {
	case common.MsgConnect:
		if int(hdr.PayloadLen) != len(payload) {
			http.Error(w, "Bad Request", 400)
			return
		}
		req, err := common.DecodeConnectRequest(payload)
		if err != nil {
			log.Printf("[Server] Decode connect: %v", err)
			http.Error(w, "Bad Request", 400)
			return
		}
		log.Printf("[Server] Connect -> %s", req.Address)
		h.handleConnect(w, hdr.ConnID, req)
	case common.MsgData:
		conn := h.server.getClient(hdr.ConnID)
		if conn == nil {
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if _, err := conn.remote.Write(payload); err != nil {
			log.Printf("[Server] Write to target failed connID=%d: %v", hdr.ConnID, err)
			conn.remote.Close()
			h.server.unregisterClient(hdr.ConnID)
		}
		w.Write([]byte(`{"status":"ok"}`))
	case common.MsgClose:
		conn := h.server.getClient(hdr.ConnID)
		if conn != nil {
			conn.remote.Close()
			h.server.unregisterClient(hdr.ConnID)
		}
		w.Write([]byte(`{"status":"ok"}`))
	default:
		w.Write([]byte(`{"status":"ok"}`))
	}
}

func (h *tunnelHandler) handleConnect(w http.ResponseWriter, connID uint32, req *common.ConnectRequest) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	remote, err := dialer.Dial(req.Network, req.Address)
	if err != nil {
		log.Printf("[Server] Dial %s %s: %v", req.Network, req.Address, err)
		w.Write([]byte(`{"status":"error","msg":"connect failed"}`))
		return
	}

	cc := &clientConn{
		connID:     connID,
		remote:     remote,
		server:     h.server,
		targetAddr: req.Address,
		dataCh:     make(chan []byte, 16),
	}
	h.server.registerClient(connID, cc)

	// Start a goroutine to read from the remote connection and buffer the data.
	go func() {
		defer h.server.unregisterClient(connID)
		defer remote.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case cc.dataCh <- data:
				case <-h.server.stopCh:
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[Server] Read error from %s (connID=%d): %v", cc.targetAddr, connID, err)
				}
				break
			}
		}
		close(cc.dataCh)
	}()

	w.Write([]byte(`{"status":"ok","conn_id":` + fmt.Sprintf("%d", connID) + `}`))
}

// handleDownload streams encrypted data to the client.
func (h *tunnelHandler) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	connIDStr := strings.TrimPrefix(r.URL.Path, "/download/")
	if connIDStr == "" {
		http.Error(w, "Not Found", 404)
		return
	}

	var connID uint32
	if _, err := fmt.Sscanf(connIDStr, "%d", &connID); err != nil {
		http.Error(w, "Not Found", 404)
		return
	}

	conn := h.server.getClient(connID)
	if conn == nil {
		http.Error(w, "Not Found", 404)
		return
	}
	log.Printf("[Server] Download connID=%d -> %s", connID, conn.targetAddr)

	// Set headers for streaming
	filename := randomFilename()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", 500)
		return
	}
	flusher.Flush()

	for {
		select {
		case data, ok := <-conn.dataCh:
			if !ok {
				return // Channel closed
			}
			payload := append(
				[]byte{common.Version, common.MsgData},
				uint32ToBytes(connID)...,
			)
			payload = append(payload, uint32ToBytes(uint32(len(data)))...)
			payload = append(payload, data...)

			encrypted, err := h.server.encryptor.EncryptStream(payload)
			if err != nil {
				return
			}
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
			if _, err := w.Write(lenBuf); err != nil {
				return
			}
			if _, err := w.Write(encrypted); err != nil {
				return
			}
			flusher.Flush()
		case <-h.server.stopCh:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

type clientConn struct {
	connID     uint32
	remote     net.Conn
	server     *Server
	targetAddr string
	dataCh     chan []byte
}
