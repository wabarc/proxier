// Copyright 2023 Wayback Archiver. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package proxier // import "github.com/wabarc/proxier"

import (
	utls "github.com/refraction-networking/utls"
)

// UTLS represents a uTLS struct.
type UTLS struct {
	proxy interface{}

	clientHello *utls.ClientHelloID
	config      *utls.Config
}

// UTLSOption is a function type that modifies a UTLS struct by setting one of its fields.
type UTLSOption func(*UTLS)

// Options takes one or more UTLSOptions and returns a UTLS struct has been configured
// according to those options.
func UTLSOptions(options ...UTLSOption) UTLS {
	var u UTLS
	for _, o := range options {
		o(&u)
	}
	return u
}

// Proxy sets the proxy field of a UTLS struct to the given proxy.
func Proxy(p interface{}) UTLSOption {
	return func(o *UTLS) {
		o.proxy = p
	}
}

// ClientHello sets the clientHello field of a UTLS struct to the given clientHello.
func ClientHello(ch *utls.ClientHelloID) UTLSOption {
	return func(o *UTLS) {
		o.clientHello = ch
	}
}

// Config sets the utls config field of a UTLS struct to the given config.
func Config(c *utls.Config) UTLSOption {
	return func(o *UTLS) {
		o.config = c
	}
}
