// Copyright 2023 Wayback Archiver. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package proxier // import "github.com/wabarc/proxier"

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"

	utls "github.com/refraction-networking/utls"
)

// https://tools.ietf.org/html/rfc7231#section-4.3.6
// Conceivably we could also proxy over HTTP/2:
// https://httpwg.org/specs/rfc7540.html#CONNECT
// https://github.com/caddyserver/forwardproxy/blob/05b2092e07f9d10b3803d8fb9775d2f87dc58590/httpclient/httpclient.go

type httpProxy struct {
	network, addr string
	auth          *proxy.Auth
	forward       proxy.Dialer
}

func (pr *httpProxy) Dial(network, addr string) (net.Conn, error) {
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	// http.Transport has a ProxyConnectHeader field that we are ignoring
	// here.
	if pr.auth != nil {
		connectReq.Header.Set("Proxy-Authorization", "basic "+
			base64.StdEncoding.EncodeToString([]byte(pr.auth.User+":"+pr.auth.Password)))
	}

	conn, err := pr.forward.Dial(pr.network, pr.addr)
	if err != nil {
		return nil, err
	}

	err = connectReq.Write(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// The Go stdlib says: "Okay to use and discard buffered reader here,
	// because TLS server will not speak until spoken to."
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if br.Buffered() != 0 {
		panic(br.Buffered())
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy server returned %q", resp.Status)
	}

	return conn, nil
}

func ProxyHTTP(network, addr string, auth *proxy.Auth, forward proxy.Dialer) (*httpProxy, error) {
	return &httpProxy{
		network: network,
		addr:    addr,
		auth:    auth,
		forward: forward,
	}, nil
}

type UTLSDialer struct {
	config        *utls.Config
	clientHelloID *utls.ClientHelloID
	forward       proxy.Dialer
}

func (dialer *UTLSDialer) Dial(network, addr string) (net.Conn, error) {
	return dialUTLS(network, addr, dialer.config, dialer.clientHelloID, dialer.forward)
}

func ProxyHTTPS(network, addr string, auth *proxy.Auth, forward proxy.Dialer, cfg *utls.Config, clientHelloID *utls.ClientHelloID) (*httpProxy, error) {
	return &httpProxy{
		network: network,
		addr:    addr,
		auth:    auth,
		forward: &UTLSDialer{
			config: cfg,
			// We use the same uTLS ClientHelloID for the TLS
			// connection to the HTTPS proxy, as we use for the TLS
			// connection through the tunnel.
			clientHelloID: clientHelloID,
			forward:       forward,
		},
	}, nil
}

// Extract a host:port address from a URL, suitable for passing to net.Dial.
func addrForDial(url *url.URL) (string, error) {
	host := url.Hostname()
	// net/http would use golang.org/x/net/idna here, to convert a possible
	// internationalized domain name to ASCII.
	port := url.Port()
	if port == "" {
		// No port? Use the default for the scheme.
		switch url.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported URL scheme %q", url.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

// Analogous to tls.Dial. Connect to the given address and initiate a TLS
// handshake using the given ClientHelloID, returning the resulting connection.
func dialUTLS(network, addr string, cfg *utls.Config, clientHelloID *utls.ClientHelloID, forward proxy.Dialer) (*utls.UConn, error) {
	conn, err := forward.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, cfg, *clientHelloID)
	if cfg == nil || cfg.ServerName == "" {
		serverName, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		uconn.SetSNI(serverName)
	}
	if err = uconn.Handshake(); err != nil {
		return nil, err
	}
	return uconn, nil
}

func makeProxyDialer(p interface{}, cfg *utls.Config, clientHelloID *utls.ClientHelloID) (proxy.Dialer, *url.URL, error) {
	var (
		err         error
		proxyURL    *url.URL
		proxyDialer proxy.Dialer = proxy.Direct
	)

	switch v := p.(type) {
	case string:
		proxyURL, err = url.Parse(v)
		if err != nil {
			return proxyDialer, nil, err
		}
	case *url.URL:
		proxyURL = v
	case net.Dialer:
		uri := v.LocalAddr.String()
		proxyURL, err = url.Parse(uri)
		if err != nil {
			return proxyDialer, nil, err
		}
	default:
		return proxyDialer, proxyURL, nil
	}

	proxyAddr, err := addrForDial(proxyURL)
	if err != nil {
		return nil, proxyURL, err
	}

	var auth *proxy.Auth
	if userpass := proxyURL.User; userpass != nil {
		auth = &proxy.Auth{
			User: userpass.Username(),
		}
		if password, ok := userpass.Password(); ok {
			auth.Password = password
		}
	}

	switch proxyURL.Scheme {
	case "socks5":
		proxyDialer, err = proxy.SOCKS5("tcp", proxyAddr, auth, proxyDialer)
	case "http":
		proxyDialer, err = ProxyHTTP("tcp", proxyAddr, auth, proxyDialer)
	case "https":
		// We use the same uTLS Config for TLS to the HTTPS proxy, as we
		// use for HTTPS connections through the tunnel. We make a clone
		// of the Config to avoid concurrent modification as the two
		// layers set the ServerName value.
		var cfgClone *utls.Config
		if cfg != nil {
			cfgClone = cfg.Clone()
		}
		proxyDialer, err = ProxyHTTPS("tcp", proxyAddr, auth, proxyDialer, cfgClone, clientHelloID)
	default:
		return nil, proxyURL, fmt.Errorf("cannot use proxy scheme %q with uTLS", proxyURL.Scheme)
	}

	return proxyDialer, proxyURL, err
}
