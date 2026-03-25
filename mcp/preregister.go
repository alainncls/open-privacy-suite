package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerPreregisterTools(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	registerPreregisterAddresses(s, client)
	registerListPreregisteredAddresses(s, client)
	registerDeletePreregisteredAddress(s, client, confirms)
	registerUpdatePreregisteredABI(s, client)
}

type preregisterAddressesArgs struct {
	OrgID     string   `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Addresses []string `json:"addresses" jsonschema:"list of ETH addresses to preregister (required)"`
}

func registerPreregisterAddresses(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "preregister_addresses",
		Description: "Preregister contract addresses for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args preregisterAddressesArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || len(args.Addresses) == 0 {
			return errorResult("org_id and addresses are required")
		}
		raw, err := client.post(fmt.Sprintf("/api/v1/admin/orgs/%s/addresses/preregister", url.QueryEscape(args.OrgID)), map[string]any{
			"addresses": args.Addresses,
		})
		if err != nil {
			return errorResult("preregistering addresses: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}
		return textResult(section("Addresses Preregistered"), prettyJSON(json.RawMessage(raw)))
	})
}

func registerListPreregisteredAddresses(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_preregistered_addresses",
		Description: "List preregistered addresses for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args orgIDArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/addresses/preregistered", url.QueryEscape(args.OrgID)))
		if err != nil {
			return errorResult("listing preregistered addresses: %v", err)
		}
		return textResult(section("Preregistered Addresses"), prettyJSON(json.RawMessage(raw)))
	})
}

type deletePreregisteredAddressArgs struct {
	OrgID        string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address      string `json:"address" jsonschema:"ETH address to delete (0x-prefixed, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerDeletePreregisteredAddress(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_preregistered_address",
		Description: "Delete a preregistered address. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deletePreregisteredAddressArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("delete_preregistered_address", map[string]any{"org_id": args.OrgID, "address": args.Address})
			return textResult(
				section("Confirm Delete Preregistered Address"),
				kvf("Address", args.Address),
				"",
				kvf("Confirmation Token", token),
				"Call delete_preregistered_address again with this confirm_token to execute.",
			)
		}
		params, err := confirms.Validate(args.ConfirmToken, "delete_preregistered_address")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.del(fmt.Sprintf("/api/v1/admin/orgs/%s/addresses/preregistered/%s",
			url.QueryEscape(confirmParam(params, "org_id")), url.QueryEscape(confirmParam(params, "address"))))
		if err != nil {
			return errorResult("deleting preregistered address: %v", err)
		}
		return textResult(section("Preregistered Address Deleted"))
	})
}

type updatePreregisteredABIArgs struct {
	OrgID   string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address string `json:"address" jsonschema:"ETH address (0x-prefixed, required)"`
	ABI     string `json:"abi" jsonschema:"JSON ABI string (required)"`
}

func registerUpdatePreregisteredABI(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "update_preregistered_abi",
		Description: "Update the ABI for a preregistered address.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args updatePreregisteredABIArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" || args.ABI == "" {
			return errorResult("org_id, address, and abi are required")
		}
		raw, err := client.put(fmt.Sprintf("/api/v1/admin/orgs/%s/addresses/preregistered/%s/abi",
			url.QueryEscape(args.OrgID), url.QueryEscape(args.Address)), map[string]any{
			"abi": args.ABI,
		})
		if err != nil {
			return errorResult("updating preregistered ABI: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}
		return textResult(section("Preregistered ABI Updated"), kvf("Address", args.Address))
	})
}
