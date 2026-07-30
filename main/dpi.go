package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/lord-aali/PTBridge.git/common/configuration"
	"github.com/lord-aali/PTBridge.git/common/ptlog"
	DpiClient "github.com/lord-aali/PTBridge.git/dpi/client"
	DpiCommon "github.com/lord-aali/PTBridge.git/dpi/common"
	DpiServer "github.com/lord-aali/PTBridge.git/dpi/server"
)

const (
	dpiDefaultEncKey      = "default-encryption-key-change-me"
	dpiDefaultProtocol    = "auto"
	dpiDefaultSocksAddr   = "127.0.0.1:1080"
	dpiDefaultDnsUpstream = "1.1.1.1:53"
	dpiDefaultDnsNetwork  = "tcp"
)

// dpiOrDefault returns value if it is non-blank, otherwise fallback.
func dpiOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// launchDpiServer starts a dpi HTTP/HTTPS tunnel server from a config entry.
// It returns true once the listeners are up; the dpi server manages its own
// listeners internally, so none are surfaced to the terminal monitor.
func launchDpiServer(c configuration.JsonServerConfigImpl, tag string) bool {
	lg := ptlog.PTLog{LogTag: tag}

	cfg := DpiServer.Config{
		HTTPAddr:      c.HttpAddr,
		HTTPSAddr:     c.HttpsAddr,
		TLSCertFile:   c.TlsCertFile,
		TLSKeyFile:    c.TlsKeyFile,
		ACMEEmail:     c.AcmeEmail,
		ACMEDomain:    c.AcmeDomain,
		SelfSigned:    c.SelfSigned,
		RedirectURL:   c.Redirect,
		EncryptionKey: []byte(dpiOrDefault(c.EncKey, dpiDefaultEncKey)),
		CertDir:       c.CertDir,
		Protocol:      dpiOrDefault(c.Protocol, dpiDefaultProtocol),
	}

	if cfg.HTTPAddr == "" && cfg.HTTPSAddr == "" {
		lg.Error("dpi server requires an http and/or https listen address")
		return false
	}
	if cfg.HTTPSAddr != "" && !cfg.SelfSigned && cfg.ACMEEmail == "" && cfg.TLSCertFile == "" {
		lg.Error("dpi https requires tls-cert/tls-key, acme-email + acme-domain, or self-signed")
		return false
	}

	srv, err := DpiServer.NewServer(cfg)
	if err != nil {
		lg.Error("dpi server init failed:", err)
		return false
	}
	if err := srv.Run(); err != nil {
		lg.Error("dpi server run failed:", err)
		return false
	}
	lg.Info("dpi server started (http:", dpiOrDefault(cfg.HTTPAddr, "-"), "https:", dpiOrDefault(cfg.HTTPSAddr, "-")+")")
	return true
}

// launchDpiClient starts a dpi client's SOCKS5 and/or HTTP CONNECT proxy that
// tunnels to a dpi server over HTTP(S).
func launchDpiClient(c configuration.JsonClientConfigImpl, tag string) bool {
	lg := ptlog.PTLog{LogTag: tag}

	if strings.TrimSpace(c.Address) == "" {
		lg.Error("dpi client requires a server address (URL)")
		return false
	}

	u, err := url.Parse(c.Address)
	if err != nil {
		lg.Error("dpi client invalid server URL:", err)
		return false
	}

	dialIP := strings.TrimSpace(c.FrontIP)
	if dialIP == "" {
		dialIP, err = resolveServerIP(u)
		if err != nil {
			lg.Error("dpi client resolve server IP failed:", err)
			return false
		}
		lg.Info("Resolved", u.Hostname(), "->", dialIP)
	} else {
		ip := net.ParseIP(dialIP)
		if ip == nil {
			lg.Error("dpi client invalid front-ip:", dialIP)
			return false
		}
		if v4 := ip.To4(); v4 != nil {
			dialIP = v4.String()
		} else {
			dialIP = ip.String()
		}
	}

	encryptor, err := DpiCommon.NewEncryptor([]byte(dpiOrDefault(c.EncKey, dpiDefaultEncKey)))
	if err != nil {
		lg.Error("dpi client encryptor failed:", err)
		return false
	}

	sniOverride := c.Sni
	if sniOverride == "" {
		sniOverride = u.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName:         sniOverride,
		InsecureSkipVerify: c.Insecure,
	}

	followRedirects := true
	if c.FollowRedirect != nil {
		followRedirects = *c.FollowRedirect
	}

	transport, err := DpiClient.NewTransport(c.Address, encryptor, tlsConfig, followRedirects, c.FrontHost, dialIP, dpiOrDefault(c.Protocol, dpiDefaultProtocol))
	if err != nil {
		lg.Error("dpi client transport failed:", err)
		return false
	}

	// Default the SOCKS listener only when no HTTP proxy is configured either,
	// matching the standalone dpi-proxy behaviour.
	socksAddr := c.Listen
	if socksAddr == "" && c.HttpProxyAddr == "" {
		socksAddr = dpiDefaultSocksAddr
	}

	proxyCfg := DpiClient.ProxyConfig{
		Transport:   transport,
		SOCKSAddr:   socksAddr,
		HTTPAddr:    c.HttpProxyAddr,
		DNSUpstream: dpiOrDefault(c.DnsUpstream, dpiDefaultDnsUpstream),
		DNSNetwork:  dpiOrDefault(c.DnsNetwork, dpiDefaultDnsNetwork),
		Verbose:     c.Verbose,
	}

	proxy := DpiClient.NewProxyServer(proxyCfg)
	if err := proxy.Run(); err != nil {
		lg.Error("dpi client proxy run failed:", err)
		return false
	}
	lg.Info("dpi client started (socks:", dpiOrDefault(socksAddr, "-"), "http-proxy:", dpiOrDefault(c.HttpProxyAddr, "-")+")")
	return true
}

// resolveServerIP returns the dial IP for the dpi server hostname. The lookup
// runs once at startup, mirroring the standalone dpi-proxy client.
func resolveServerIP(u *url.URL) (string, error) {
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("server URL has no hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return ip.String(), nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("lookup %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("lookup %s: no addresses", host)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return ips[0].String(), nil
}
