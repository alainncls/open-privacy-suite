package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerSystemTools(s *mcp.Server, client *httpClient) {
	registerHealth(s, client)
	registerStatus(s, client)
	registerTestRequest(s, client)
	registerEthAddressCollisions(s, client)
}

func registerHealth(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "health",
		Description: "Check if the privacy proxy is reachable.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/health")
		if err != nil {
			return errorResult("Privacy proxy unreachable: %v\n\nIs it running? Try: docker-compose up -d", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return errorResult("parsing response: %v", err)
		}
		return textResult(
			section("Privacy Proxy Health: OK"),
			kvf("Status", getString(m, "status")),
		)
	})
}

func registerStatus(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "status",
		Description: "Get privacy proxy status: proxy state, node connectivity, and security config.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/status")
		if err != nil {
			return errorResult("Status failed: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return errorResult("Parsing status: %v", err)
		}

		lines := section("Privacy Proxy Status") + "\n"

		if proxy := getMap(m, "proxy"); proxy != nil {
			lines += joinLines(
				kvf("Proxy Status", getString(proxy, "status")),
				kvf("Proxy Port", getString(proxy, "port")),
			) + "\n"
		}

		if node := getMap(m, "node"); node != nil {
			lines += joinLines(
				kvf("Node Status", getString(node, "status")),
				kvf("Node URL", getString(node, "url")),
				kvf("Node Latency", fmt.Sprintf("%dms", int64(getFloat(node, "latency_ms")))),
			) + "\n"
		}

		if sec := getMap(m, "security"); sec != nil {
			lines += kvf("Runtime Tracing", boolYesNo(getBool(sec, "runtime_tracing_enabled")))
		}

		return textResult(lines)
	})
}

type testRequestArgs struct {
	Method         string `json:"method" jsonschema:"JSON-RPC method to test (e.g. eth_call, required)"`
	Params         any    `json:"params,omitempty" jsonschema:"JSON-RPC params (array or object)"`
	UserExternalID string `json:"user_external_id,omitempty" jsonschema:"user DID to test as"`
}

func registerTestRequest(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "test_request",
		Description: "Send a test JSON-RPC request through the proxy pipeline to verify RBAC, compliance, and filtering.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args testRequestArgs) (*mcp.CallToolResult, any, error) {
		if args.Method == "" {
			return errorResult("method is required")
		}
		body := map[string]any{"method": args.Method}
		if args.Params != nil {
			body["params"] = args.Params
		}
		if args.UserExternalID != "" {
			body["user_external_id"] = args.UserExternalID
		}
		raw, err := client.post("/api/v1/admin/test-request", body)
		if err != nil {
			return errorResult("test request failed: %v", err)
		}
		return textResult(section("Test Request Result"), prettyJSON(json.RawMessage(raw)))
	})
}

func registerEthAddressCollisions(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "eth_address_collisions",
		Description: "Check for ETH address collisions across users.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/eth-addresses/collisions")
		if err != nil {
			return errorResult("checking address collisions: %v", err)
		}
		return textResult(section("ETH Address Collisions"), prettyJSON(json.RawMessage(raw)))
	})
}
