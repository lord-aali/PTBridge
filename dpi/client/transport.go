package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lord-aali/PTBridge.git/dpi/common"
)

// Transport sends/receives encrypted data over HTTP to the server.
type Transport struct {
	baseURL    string
	scheme     string
	host       string
	frontHost  string
	frontIP    string
	encryptor  *common.Encryptor
	httpClient *http.Client
	protocol   string
	connIDGen  uint32
	connIDMu   sync.Mutex
}

// NewTransport creates a transport to the server.
func NewTransport(serverURL string, encryptor *common.Encryptor, tlsConfig *tls.Config, followRedirects bool, frontHost, frontIP, protocol string) (*Transport, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL scheme must be http or https")
	}

	if frontIP == "" {
		return nil, fmt.Errorf("front IP is required (resolve from -server at startup)")
	}
	proto, err := normalizeAppProtocol(protocol)
	if err != nil {
		return nil, err
	}

	tr := &Transport{
		baseURL:   serverURL,
		scheme:    u.Scheme,
		host:      u.Host,
		frontHost: frontHost,
		frontIP:   frontIP,
		encryptor: encryptor,
		protocol:  proto,
	}
	tr.connIDGen = 1

	transport := &http.Transport{
		MaxIdleConns:        256,
		IdleConnTimeout:     120 * time.Second,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 128,
		ForceAttemptHTTP2:   proto != "h1",
		TLSClientConfig:     tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Force connection to front IP if the address matches the server's host
			if strings.Contains(addr, u.Hostname()) {
				// Preserve the original port
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					// Default to 443 for https, 80 for http if port is missing
					if u.Scheme == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
				addr = net.JoinHostPort(tr.frontIP, port)
			}
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	if proto == "h1" {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	// Use the provided tlsConfig, which is correctly configured in main.go
	tr.httpClient = &http.Client{Transport: transport}

	if !followRedirects {
		tr.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return tr, nil
}

// NextConnID returns a new connection ID.
func (t *Transport) NextConnID() uint32 {
	t.connIDMu.Lock()
	defer t.connIDMu.Unlock()
	id := t.connIDGen
	t.connIDGen++
	if t.connIDGen == 0 {
		t.connIDGen = 1
	}
	return id
}

// Connect establishes a tunneled connection to target.
func (t *Transport) Connect(network, address string) (uint32, error) {
	req := &common.ConnectRequest{Network: network, Address: address}
	payload := common.EncodeConnectRequest(req)
	connID := t.NextConnID()

	header := make([]byte, common.StreamHeaderSize)
	header[0] = common.Version
	header[1] = common.MsgConnect
	binary.BigEndian.PutUint32(header[2:6], connID)
	binary.BigEndian.PutUint32(header[6:10], uint32(len(payload)))

	plaintext := append(header, payload...)
	encrypted, err := t.encryptor.Encrypt(plaintext)
	if err != nil {
		return 0, err
	}

	uploadURL := t.baseURL + "/.well-known/cdn-cache/upload"
	httpReq, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(encrypted))
	if err != nil {
		return 0, err
	}
	t.setBrowserHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
		redirectURL := resp.Header.Get("Location")
		if redirectURL[0] == '/' {
			redirectURL = t.scheme + "://" + t.host + redirectURL
		}
		t.baseURL = redirectURL
		return t.Connect(network, address)
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("connect failed: %s", string(body))
	}
	if !bytes.Contains(body, []byte(`"status":"ok"`)) {
		return 0, fmt.Errorf("connect failed: %s", string(body))
	}
	return connID, nil
}

// SendData sends data to the server (POST method).
func (t *Transport) SendData(connID uint32, data []byte) error {
	header := make([]byte, common.StreamHeaderSize)
	header[0] = common.Version
	header[1] = common.MsgData
	binary.BigEndian.PutUint32(header[2:6], connID)
	binary.BigEndian.PutUint32(header[6:10], uint32(len(data)))

	plaintext := append(header, data...)
	encrypted, err := t.encryptor.Encrypt(plaintext)
	if err != nil {
		return err
	}

	uploadURL := t.baseURL + "/api/v2/upload"
	httpReq, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(encrypted))
	if err != nil {
		return err
	}
	t.setBrowserHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// CloseConn tells the server to close the connection.
func (t *Transport) CloseConn(connID uint32) error {
	header := make([]byte, common.StreamHeaderSize)
	header[0] = common.Version
	header[1] = common.MsgClose
	binary.BigEndian.PutUint32(header[2:6], connID)
	binary.BigEndian.PutUint32(header[6:10], 0)

	encrypted, err := t.encryptor.Encrypt(header)
	if err != nil {
		return err
	}

	uploadURL := t.baseURL + "/api/v2/upload"
	httpReq, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(encrypted))
	if err != nil {
		return err
	}
	t.setBrowserHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// DownloadStream opens a GET request to stream download data. Returns a reader that yields decrypted chunks.
func (t *Transport) DownloadStream(ctx context.Context, connID uint32) (io.ReadCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	downloadURL := fmt.Sprintf("%s/download/%d", t.baseURL, connID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}
	t.setBrowserHeaders(httpReq)
	httpReq.Header.Del("Accept-Encoding")

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download failed: %d", resp.StatusCode)
	}

	return &streamReader{
		resp:      resp,
		encryptor: t.encryptor,
	}, nil
}

type streamReader struct {
	resp      *http.Response
	encryptor *common.Encryptor
	buf       []byte
	decrypted []byte
	off       int
}

func (sr *streamReader) Read(p []byte) (int, error) {
	for {
		if sr.off < len(sr.decrypted) {
			n := copy(p, sr.decrypted[sr.off:])
			sr.off += n
			return n, nil
		}
		sr.decrypted = nil
		sr.off = 0

		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(sr.resp.Body, lenBuf); err != nil {
			return 0, err
		}
		encLen := binary.BigEndian.Uint32(lenBuf)
		if encLen > 256*1024 {
			return 0, io.ErrClosedPipe
		}

		if sr.buf == nil || cap(sr.buf) < int(encLen) {
			sr.buf = make([]byte, encLen)
		}
		if _, err := io.ReadFull(sr.resp.Body, sr.buf[:encLen]); err != nil {
			return 0, err
		}
		dec, err := sr.encryptor.Decrypt(sr.buf[:encLen])
		if err != nil {
			return 0, err
		}
		if len(dec) > 10 {
			payloadLen := binary.BigEndian.Uint32(dec[6:10])
			if int(10+payloadLen) <= len(dec) {
				sr.decrypted = dec[10 : 10+payloadLen]
			}
		}
	}
}

func (sr *streamReader) Close() error {
	return sr.resp.Body.Close()
}

func (t *Transport) setBrowserHeaders(req *http.Request) {
	// Use dynamic frontHost if provided
	if t.frontHost != "" {
		req.Host = t.frontHost
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
}

func normalizeAppProtocol(protocol string) (string, error) {
	switch protocol {
	case "", "auto":
		return "auto", nil
	case "h1", "h2":
		return protocol, nil
	case "h3":
		return "", fmt.Errorf("protocol h3 is not implemented yet")
	default:
		return "", fmt.Errorf("invalid protocol %q (expected auto, h1, h2, or h3)", protocol)
	}
}
