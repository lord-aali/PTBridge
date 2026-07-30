package configuration

import (
	"encoding/json"
	"github.com/lord-aali/PTBridge.git/common/ptlog"
	"os"
)

const MODE_SERVER = "SERVER"
const MODE_CLIENT = "CLIENT"
const MODE_BRIDGE = "BRIDGE"
const MODE_INTERNAL = "INTERNAL"
const MODE_EXTERNAL = "EXTERNAL"
const TRANSPORT_OBFS = "OBFSx"

// ObfsIatMode is the fixed obfs4 inter-arrival-time mode used by this proxy.
// It is intentionally not configurable: only "0" (disabled) is supported.
const ObfsIatMode = "0"

var Mode = MODE_SERVER
var Transport = TRANSPORT_OBFS
var WorkingDirectory = "./"
var Config = JsonConfigImpl{}

type JsonConfigImpl struct {
	Server []JsonServerConfigImpl `json:"server"`
	Client []JsonClientConfigImpl `json:"client"`
}

type JsonServerConfigImpl struct {
	Type                   string `json:"type"`                  // obfs2-4, dpi
	Listen                 string `json:"listen"`                // 127.0.0.1:4455
	UseExternalService     bool   `json:"external"`              // false
	ExternalServiceAddress string `json:"external-service"`      // 127.0.0.1:1234
	Cert                   string `json:"cert,omitempty"`        // obfs4 client certificate (auto-generated if empty)
	PrivateKey             string `json:"private-key,omitempty"` // obfs4 server private key paired with Cert

	// dpi transport fields (type == "dpi").
	EncKey      string `json:"enc-key,omitempty"`     // shared encryption key
	Protocol    string `json:"protocol,omitempty"`    // auto, h1, h2
	HttpAddr    string `json:"http,omitempty"`        // HTTP listen address, e.g. :8080
	HttpsAddr   string `json:"https,omitempty"`       // HTTPS listen address, e.g. :443
	TlsCertFile string `json:"tls-cert,omitempty"`    // TLS certificate file path
	TlsKeyFile  string `json:"tls-key,omitempty"`     // TLS private key file path
	AcmeEmail   string `json:"acme-email,omitempty"`  // Let's Encrypt ACME email
	AcmeDomain  string `json:"acme-domain,omitempty"` // Let's Encrypt domain
	SelfSigned  bool   `json:"self-signed,omitempty"` // use a self-signed certificate
	Redirect    string `json:"redirect,omitempty"`    // redirect browsers to this URL
	CertDir     string `json:"cert-dir,omitempty"`    // ACME certificate storage directory

	// snowflake transport fields (type == "snowflake"). Reuses Listen as the
	// WebSocket listen address and TlsCertFile/TlsKeyFile to enable WSS.
	SocksBind string `json:"socks-bind,omitempty"` // server SOCKS5 exit listen address
}

type JsonClientConfigImpl struct {
	// Generic client fields shared by all transports. For dpi/snowflake,
	// Address holds the server URL (http(s)://, ws(s)://) and Listen holds the
	// local SOCKS5 listen address, mirroring the obfs series.
	Type               string `json:"type"`     // obfs2-4, dpi, snowflake
	Listen             string `json:"listen"`   // local listen address (obfs / dpi+snowflake SOCKS5)
	Address            string `json:"address"`  // server address (obfs host:port / dpi+snowflake URL)
	UseExternalService bool   `json:"external"` // false
	Cert               string `json:"cert"`     // xxXxxxXXXXXXxxxxx

	// dpi transport fields (type == "dpi").
	EncKey         string `json:"enc-key,omitempty"`         // shared encryption key
	Protocol       string `json:"protocol,omitempty"`        // auto, h1, h2
	Sni            string `json:"sni,omitempty"`             // override TLS SNI
	Insecure       bool   `json:"insecure,omitempty"`        // accept self-signed / untrusted server certs
	HttpProxyAddr  string `json:"http-proxy,omitempty"`      // HTTP CONNECT proxy listen address
	FollowRedirect *bool  `json:"redirect-follow,omitempty"` // follow HTTP redirects (default true)
	DnsUpstream    string `json:"dns-upstream,omitempty"`    // upstream DNS resolver IP:port
	DnsNetwork     string `json:"dns-network,omitempty"`     // dns transport: tcp or udp
	FrontHost      string `json:"front-host,omitempty"`      // domain fronting Host header
	FrontIP        string `json:"front-ip,omitempty"`        // dial IP override
	Verbose        bool   `json:"verbose,omitempty"`         // verbose client logging

	// snowflake transport fields (type == "snowflake"). Reuses Address as the
	// ws(s):// server URL, Insecure for wss cert skipping, Listen as the local
	// SOCKS5 listen address, Sni as the TLS SNI override, and FrontHost as the
	// custom WebSocket Host header (domain fronting).
	Proxy       string `json:"proxy,omitempty"`        // upstream SOCKS5/HTTP proxy to reach the server
	ForwardBind string `json:"forward-bind,omitempty"` // local address forwarding to the server SOCKS exit
}

func Load(path string) JsonConfigImpl {
	lg := ptlog.PTLog{"system"}
	lg.Info("Loading config file:", path)
	bytes, err := os.ReadFile(path)
	if err != nil {
		lg.Fatal("Can't access the config file", err)
	}

	err = json.Unmarshal(bytes, &Config)
	if err != nil {
		lg.Fatal("Failed to parse config file", err)
	}
	lg.Info("Loaded successfully...")
	return Config
}

// Save writes the given config back to disk as indented JSON. It is used to
// persist auto-generated obfs4 certificates so they remain stable across
// restarts.
func Save(path string, config JsonConfigImpl) error {
	lg := ptlog.PTLog{LogTag: "system"}
	bytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, bytes, 0o644); err != nil {
		return err
	}
	lg.Info("Saved config file:", path)
	return nil
}