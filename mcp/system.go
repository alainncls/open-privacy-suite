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
		json.Unmarshal(raw, &m)
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

		if label := client.perspective.Label(); label != "" {
			lines = label + "\n\n" + lines
		}

		return textResult(lines)
	})
}
