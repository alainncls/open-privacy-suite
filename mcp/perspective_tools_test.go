package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestWhoAmI_DefaultAdmin(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerPerspectiveTools(s, client)
	})

	text := callTool(t, env, "who_am_i", struct{}{})
	if !strings.Contains(text, "Admin") {
		t.Fatalf("expected Admin perspective, got: %s", text)
	}
}

func TestSetPerspective_ByID(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/admin/users/user-123" {
			fmt.Fprint(w, `{"id":"user-123","external_id":"did:pkh:eip155:1:0xBOB"}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerPerspectiveTools(s, client)
	})

	text := callTool(t, env, "set_perspective", setPerspectiveArgs{Query: "user-123"})
	if !strings.Contains(text, "Perspective Set") {
		t.Fatalf("expected perspective set, got: %s", text)
	}
	if !strings.Contains(text, "did:pkh:eip155:1:0xBOB") {
		t.Fatalf("expected DID in output, got: %s", text)
	}

	if client.perspective == nil || !client.perspective.Active {
		t.Fatal("perspective should be active")
	}
	if client.perspective.UserID != "user-123" {
		t.Fatalf("expected user-123, got %s", client.perspective.UserID)
	}
	if client.perspective.Level != 1 {
		t.Fatalf("expected level 1, got %d", client.perspective.Level)
	}
}

func TestSetPerspective_BySearch(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/admin/users/0xBOB" {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/users") {
			search := r.URL.Query().Get("search")
			if search == "0xBOB" {
				fmt.Fprint(w, `{"data":[{"id":"user-456","external_id":"did:pkh:eip155:1:0xBOB"}],"total":1}`)
			} else {
				fmt.Fprint(w, `{"data":[],"total":0}`)
			}
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerPerspectiveTools(s, client)
	})

	text := callTool(t, env, "set_perspective", setPerspectiveArgs{Query: "0xBOB"})
	if !strings.Contains(text, "Perspective Set") {
		t.Fatalf("expected perspective set, got: %s", text)
	}
	if client.perspective.UserID != "user-456" {
		t.Fatalf("expected user-456, got %s", client.perspective.UserID)
	}
}

func TestSetPerspective_Ambiguous(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/admin/users/0x") {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/users") {
			fmt.Fprint(w, `{"data":[{"id":"u1","external_id":"did:a"},{"id":"u2","external_id":"did:b"}],"total":2}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerPerspectiveTools(s, client)
	})

	text := callTool(t, env, "set_perspective", setPerspectiveArgs{Query: "0xAMBIG"})
	if !strings.Contains(text, "Multiple users") {
		t.Fatalf("expected ambiguity message, got: %s", text)
	}
	if client.perspective != nil && client.perspective.Active {
		t.Fatal("perspective should NOT be set for ambiguous results")
	}
}

func TestSetPerspective_NotFound(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/admin/users/nobody") {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/users") {
			fmt.Fprint(w, `{"data":[],"total":0}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerPerspectiveTools(s, client)
	})

	text := callTool(t, env, "set_perspective", setPerspectiveArgs{Query: "nobody"})
	if !strings.Contains(text, "no user found") {
		t.Fatalf("expected not found, got: %s", text)
	}
}

func TestClearPerspective(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {})
	defer cleanup()

	client.perspective = &Perspective{Active: true, UserID: "u1", UserName: "Bob", Level: 1}

	env := setupMCP(t, func(s *mcp.Server) {
		registerPerspectiveTools(s, client)
	})

	text := callTool(t, env, "clear_perspective", struct{}{})
	if !strings.Contains(text, "Cleared") {
		t.Fatalf("expected cleared, got: %s", text)
	}
	if !strings.Contains(text, "Bob") {
		t.Fatalf("expected previous user mentioned, got: %s", text)
	}
	if client.perspective != nil {
		t.Fatal("perspective should be nil after clear")
	}
}

func TestClearPerspective_AlreadyAdmin(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerPerspectiveTools(s, client)
	})

	text := callTool(t, env, "clear_perspective", struct{}{})
	if !strings.Contains(text, "Already viewing as admin") {
		t.Fatalf("expected already admin, got: %s", text)
	}
}

func TestWhatCanUserSee(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/admin/users/user-1":
			fmt.Fprint(w, `{"id":"user-1","external_id":"did:test","banned":false}`)
		case r.URL.Path == "/api/v1/admin/users/user-1/linked-addresses":
			fmt.Fprint(w, `{"addresses":[{"address":"0xAAA","ens_name":"bob.eth"}]}`)
		case r.URL.Path == "/api/v1/admin/users/user-1/memberships":
			fmt.Fprint(w, `[{"membership":{"id":"m1"},"group":{"name":"Devs","path":"default.devs","is_org_admin":false}}]`)
		case strings.Contains(r.URL.Path, "effective-permissions"):
			fmt.Fprint(w, `{"user_id":"user-1","org_id":"org-1","claims":["read","write"],"allowed_methods":["eth_call","eth_getBalance"],"contract_access":{"0xDEAD":{"claims":["read"]}},"rate_limit_rps":100}`)
		default:
			http.NotFound(w, r)
		}
	})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerPerspectiveTools(s, client)
	})

	text := callTool(t, env, "what_can_user_see", whatCanUserSeeArgs{UserID: "user-1"})

	checks := []string{"did:test", "0xAAA", "bob.eth", "Devs", "eth_call", "read", "write", "0xDEAD"}
	for _, check := range checks {
		if !strings.Contains(text, check) {
			t.Fatalf("expected %q in output, got: %s", check, text)
		}
	}
}
