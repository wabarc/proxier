// Copyright 2023 Wayback Archiver. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package proxier // import "github.com/wabarc/proxier"

import (
	"net/http"
	"time"
)

const timeout = 30 * time.Second

// The Client struct wraps an http.Client and provides a higher-level interface
// for making HTTP requests. It can be used to customize the behavior of the
// client, such as specify timeouts.
type Client struct {
	*http.Client
}

// NewClient returns a new instance of the Client struct with the specified
// HTTP client. If no client is provided as an argument, a default client with
// a default timeout value is created. This function is a constructor method
// and returns a pointer to the new Client instance.
func NewClient(client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	return &Client{client}
}

type Server struct {
}

func (s *Server) Serve() {
}
