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

var (
	endpoint = `https://tls.peet.ws/api/clean`
	ja3      = `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0`
)

type Fingerprint struct {
	JA3        string `json:"ja3"`
	JA3Hash    string `json:"ja3_hash"`
	Akamai     string `json:"akamai"`
	AkamaiHash string `json:"akamai_hash"`
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

	var fp Fingerprint
	if err := json.Unmarshal(buf, &fp); err != nil {
		t.Fatalf("unexpected unmarshal json: %v", err)
	}
	if fp.JA3 != ja3 {
		t.Errorf("unexpected fingerprint, got %s instead of %s", fp.JA3, ja3)
	}
}
