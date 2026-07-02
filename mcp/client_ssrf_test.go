package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// SEC-1325 regression tests. The MCP admin client talks to one trusted upstream
// (the configured base URL). It must NOT be steerable off that host — neither by
// an HTTP redirect the upstream returns, nor by a caller-supplied path that
// embeds a different host/scheme. Both are SSRF vectors toward loopback / cloud
// metadata (169.254.169.254). These exercise the two mitigations:
//   - newHTTPClient: CheckRedirect => http.ErrUseLastResponse (never follow)
//   - do():          re-assert scheme/host/user from the trusted base URL
// Written from the SSRF spec, not from current output: each fails if its
// mitigation regresses (verified by temporarily removing CheckRedirect).

func TestClientDoesNotFollowRedirects_SEC1325(t *testing.T) {
	var metadataHit atomic.Bool
	// Stand-in for an internal / cloud-metadata endpoint a redirect might target.
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataHit.Store(true)
		_, _ = w.Write([]byte(`{"imds":"secret"}`))
	}))
	defer metadata.Close()

	// The trusted upstream 302-redirects toward that endpoint.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, metadata.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer upstream.Close()

	c, err := newHTTPClient(upstream.URL, "tok")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}

	// The 302 must NOT be followed — we don't care what do() returns for it,
	// only that the redirect target was never contacted.
	_, _ = c.get("/anything")

	if metadataHit.Load() {
		t.Fatal("SEC-1325: client followed a redirect to the metadata endpoint (SSRF)")
	}
}

func TestClientPathCannotChangeHost_SEC1325(t *testing.T) {
	var gotHost atomic.Value // string — the Host the upstream actually received
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	c, err := newHTTPClient(upstream.URL, "tok")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}

	// Each "path" embeds a foreign host/scheme. The request must still land on
	// the configured upstream host — never on the embedded one.
	for _, evilPath := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"//169.254.169.254/x",
		"https://evil.example.com/pwn",
	} {
		gotHost.Store("")
		_, _ = c.get(evilPath)
		got, _ := gotHost.Load().(string)
		if got == "" {
			t.Fatalf("path %q: the trusted upstream was never contacted", evilPath)
		}
		if got != base.Host {
			t.Fatalf("SEC-1325: path %q reached host %q, want the configured upstream %q", evilPath, got, base.Host)
		}
	}
}
