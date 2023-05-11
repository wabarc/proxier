//go:build !integration

package proxier

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/posener/h2conn"
	"github.com/posener/h2conn/h2test"

	utls "github.com/refraction-networking/utls"
)

func TestNewClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))

	var httpTransport http.RoundTripper = &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse(ts.URL)
		},
	}

	tests := []struct {
		transport http.RoundTripper
	}{
		{nil},
		{httpTransport},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			client := &http.Client{}
			client.Transport = tt.transport
			proxier := NewClient(client)
			resp, err := proxier.Get(ts.URL)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
			}
		})
	}
}

func TestH2Client(t *testing.T) {
	var serverConn *h2conn.Conn

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		serverConn, err = h2conn.Accept(w, r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer serverConn.Close()

		// simple read loop that echos the upper case of what was read.
		buf := bufio.NewReader(serverConn)
		for {
			msg, _, err := buf.ReadLine()
			if err != nil {
				t.Logf("Server failed read: %s", err)
				break
			}

			_, err = serverConn.Write(append(bytes.ToUpper(msg), '\n'))
			if err != nil {
				t.Logf("Server failed write: %s", err)
				break
			}
		}
	})
	server := h2test.NewServer(handler)
	defer server.Close()

	proxier := NewClient(nil)

	rt, _ := NewUTLSRoundTripper(Config(&utls.Config{InsecureSkipVerify: true}))
	proxier.Client.Transport = rt

	// Create a client, that uses the HTTP PUT method.
	c := h2conn.Client{Method: http.MethodPut, Client: proxier.Client}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Connect to the HTTP2 server
	// The returned conn can be used to:
	//   1. Write - send data to the server.
	//   2. Read - receive data from the server.
	conn, _, err := c.Connect(ctx, server.URL)
	if err != nil {
		t.Fatalf("connect err: %v", err)
	}
	conn.Close()
}
