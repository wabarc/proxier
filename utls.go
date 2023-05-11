// Copyright 2023 Wayback Archiver. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package proxier

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	utls "github.com/refraction-networking/utls"
)

var defaultClientHelloID = &utls.HelloChrome_102

// A http.RoundTripper that uses uTLS (with a specified Client Hello ID) to make
// TLS connections.
//
// Can only be reused among servers which negotiate the same ALPN.
type UTLSRoundTripper struct {
	clientHelloID *utls.ClientHelloID
	config        *utls.Config

	proxyDialer proxy.Dialer

	rtLock sync.Mutex
	rt     http.RoundTripper

	// Transport for HTTP requests, which don't use uTLS.
	httpRT *http.Transport
}

// RoundTrip executes a single HTTP transaction, using the UTLS protocol for secure connections.
// It takes an `http.Request` and returns an `http.Response` and an error.
// This method is used in an HTTP client to send a request and receive a response.
func (u *UTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "http":
		// If http, we don't invoke uTLS; just pass it to an ordinary http.Transport.
		return u.httpRT.RoundTrip(req)
	case "https":
		return u.httpsRoundTrip(req)
	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", req.URL.Scheme)
	}
}

func (u *UTLSRoundTripper) httpsRoundTrip(req *http.Request) (*http.Response, error) {
	var err error
	u.rtLock.Lock()
	if u.rt == nil {
		// On the first call, make an http.Transport or http2.Transport
		// as appropriate.
		u.rt, err = u.makeRoundTripper(req.URL)
	}
	u.rtLock.Unlock()
	if err != nil {
		return nil, err
	}

	if req.UserAgent() == "" {
		req.Header.Set("User-Agent", useragent)
	}

	// Forward the request to the internal http.Transport or http2.Transport.
	return u.rt.RoundTrip(req)
}

func (u *UTLSRoundTripper) makeRoundTripper(url *url.URL) (http.RoundTripper, error) {
	addr, err := addrForDial(url)
	if err != nil {
		return nil, err
	}

	// Connect to the given address, through a proxy if requested, and
	// initiate a TLS handshake using the given ClientHelloID. Return the
	// resulting connection.
	dial := func(network, addr string) (*utls.UConn, error) {
		return dialUTLS(network, addr, u.config, u.clientHelloID, u.proxyDialer)
	}

	bootstrapConn, err := dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Peek at what protocol we negotiated.
	protocol := bootstrapConn.ConnectionState().NegotiatedProtocol

	// Protects bootstrapConn.
	var lock sync.Mutex
	// This is the callback for future dials done by the internal
	// http.Transport or http2.Transport.
	dialTLS := func(network, addr string) (net.Conn, error) {
		lock.Lock()
		defer lock.Unlock()

		// On the first dial, reuse bootstrapConn.
		if bootstrapConn != nil {
			uconn := bootstrapConn
			bootstrapConn = nil
			return uconn, nil
		}

		// Later dials make a new connection.
		uconn, err := dial(network, addr)
		if err != nil {
			return nil, err
		}
		if uconn.ConnectionState().NegotiatedProtocol != protocol {
			return nil, fmt.Errorf("unexpected switch from ALPN %q to %q",
				protocol, uconn.ConnectionState().NegotiatedProtocol)
		}

		return uconn, nil
	}

	// Construct an http.Transport or http2.Transport depending on ALPN.
	switch protocol {
	case http2.NextProtoTLS:
		// Unfortunately http2.Transport does not expose the same
		// configuration options as http.Transport with regard to
		// timeouts, etc., so we are at the mercy of the defaults.
		// https://github.com/golang/go/issues/16581
		return &http2.Transport{
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				// Ignore the *tls.Config parameter; use our
				// static cfg instead.
				return dialTLS(network, addr)
			},
		}, nil
	default:
		// With http.Transport, copy important default fields from
		// http.DefaultTransport, such as TLSHandshakeTimeout and
		// IdleConnTimeout, before overriding DialTLS.
		tr := httpRoundTripper.Clone()
		tr.DialTLS = dialTLS
		return tr, nil
	}
}

// NewUTLSRoundTripper creates a new round tripper that can be used in an HTTP
// client to handle secure connections using the UTLS protocol.
//
// It takes an optional list of `UTLSOption` arguments that can be used to
// customize the behavior of the round tripper. It returns an `http.RoundTripper`
// and an error.
func NewUTLSRoundTripper(opts ...UTLSOption) (http.RoundTripper, error) {
	u := UTLSOptions(opts...)

	var (
		err error

		proxyURL *url.URL

		rt = &UTLSRoundTripper{
			clientHelloID: u.clientHello,
			config:        u.config,
		}
	)

	rt.proxyDialer, proxyURL, err = makeProxyDialer(u.proxy, u.config, u.clientHello)
	if err != nil {
		return nil, fmt.Errorf("make proxy dialer failed: %w", err)
	}

	// This special-case RoundTripper is used for HTTP requests, which don't
	// use uTLS but should use the specified proxy.
	httpRT := httpRoundTripper.Clone()
	httpRT.Proxy = http.ProxyURL(proxyURL)

	rt.httpRT = httpRT

	return rt, nil
}
