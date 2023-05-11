//go:build integration

package proxier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

var endpoint = `https://tls.peet.ws/api/all`

type response struct {
	HTTPversion string `json:"http_version"`
	Method      string `json:"method"`
	UserAgent   string `json:"user_agent"`
}

func TestClient(t *testing.T) {
	proxier := NewClient(nil)
	proxier.Client.Transport, _ = NewUTLSRoundTripper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatalf("unexpected new request: %v", err)
	}

	resp, err := proxier.Do(req)
	if err != nil {
		t.Fatalf("unexpected request: %v", err)
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unexpected read body: %v", err)
	}

	var out response
	if err := json.Unmarshal(buf, &out); err != nil {
		t.Fatalf("unexpected unmarshal json: %v", err)
	}
	if out.UserAgent != useragent {
		t.Errorf("unexpected request")
	}
}
