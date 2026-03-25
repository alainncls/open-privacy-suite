package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerProxyTools(s *mcp.Server, client *httpClient) {
	registerRegisterManagedProxy(s, client)
	registerListManagedProxies(s, client)
}

type registerManagedProxyArgs struct {
	OrgID   string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address string `json:"address" jsonschema:"proxy contract address (0x-prefixed, required)"`
	Name    string `json:"name,omitempty" jsonschema:"optional display name"`
}

func registerRegisterManagedProxy(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "register_managed_proxy",
		Description: "Register a managed proxy contract for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args registerManagedProxyArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		body := map[string]any{"address": args.Address}
		if args.Name != "" {
			body["name"] = args.Name
		}
		raw, err := client.post(fmt.Sprintf("/api/v1/admin/orgs/%s/proxies", url.QueryEscape(args.OrgID)), body)
		if err != nil {
			return errorResult("registering managed proxy: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}
		return textResult(
			section("Managed Proxy Registered"),
			kvf("Address", getString(resp, "address")),
			kvf("Name", getString(resp, "name")),
		)
	})
}

func registerListManagedProxies(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_managed_proxies",
		Description: "List managed proxy contracts for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args orgIDArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/proxies", url.QueryEscape(args.OrgID)))
		if err != nil {
			return errorResult("listing managed proxies: %v", err)
		}
		return textResult(section("Managed Proxies"), prettyJSON(json.RawMessage(raw)))
	})
}
