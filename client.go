package proxier

import (
	"net/http"
	"time"
)

const (
	timeout   = 30 * time.Second
	useragent = `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36`
)

var (
	httpRoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	client           = &http.Client{}
)

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
