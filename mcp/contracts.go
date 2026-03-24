package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerContractTools(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	registerListContracts(s, client)
	registerGetContract(s, client)
	registerCreateContract(s, client)
	registerUpdateContract(s, client)
	registerDeleteContract(s, client, confirms)
	registerListGrants(s, client)
	registerCreateGrant(s, client)
	registerDeleteGrant(s, client, confirms)
	registerLookupContract(s, client)
	registerGrantSummary(s, client)
}

type listContractsArgs struct {
	OrgID  string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max entries (default 50)"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
}

func registerListContracts(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_contracts",
		Description: "List contracts registered in an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listContractsArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		limit := args.Limit
		if limit == 0 {
			limit = 50
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts?limit=%d&offset=%d", args.OrgID, limit, args.Offset))
		if err != nil {
			return errorResult("listing contracts: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}

		contracts := getSlice(resp, "data")
		lines := section("Contracts") + "\n"
		lines += kvf("Total", getFloat(resp, "total")) + "\n"

		for _, c := range contracts {
			contract, ok := c.(map[string]any)
			if !ok {
				continue
			}
			lines += joinLines(
				fmt.Sprintf("\n### %s", getString(contract, "name")),
				kvf("Address", getString(contract, "address")),
				kvf("ID", getString(contract, "id")),
				kvf("Has ABI", boolYesNo(getString(contract, "abi") != "")),
			) + "\n"
		}
		return textResult(lines)
	})
}

type getContractArgs struct {
	OrgID   string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address string `json:"address" jsonschema:"contract address (0x-prefixed, required)"`
}

func registerGetContract(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_contract",
		Description: "Get details of a specific contract.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getContractArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts/%s", args.OrgID, args.Address))
		if err != nil {
			return errorResult("getting contract: %v", err)
		}
		var contract map[string]any
		if err := json.Unmarshal(raw, &contract); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Contract: "+getString(contract, "name")),
			kvf("ID", getString(contract, "id")),
			kvf("Address", getString(contract, "address")),
			kvf("Name", getString(contract, "name")),
			kvf("Has ABI", boolYesNo(getString(contract, "abi") != "")),
			kvf("Deployed By", getString(contract, "deployed_by_user_id")),
			kvf("Created", getString(contract, "created_at")),
		)
	})
}

type createContractArgs struct {
	OrgID    string         `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address  string         `json:"address" jsonschema:"contract address (0x-prefixed, required)"`
	Name     string         `json:"name,omitempty" jsonschema:"contract name"`
	Metadata map[string]any `json:"metadata,omitempty" jsonschema:"optional metadata"`
}

func registerCreateContract(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_contract",
		Description: "Register a new contract in an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args createContractArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		body := map[string]any{"address": args.Address}
		if args.Name != "" {
			body["name"] = args.Name
		}
		if args.Metadata != nil {
			body["metadata"] = args.Metadata
		}

		raw, err := client.post(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts", args.OrgID), body)
		if err != nil {
			return errorResult("creating contract: %v", err)
		}
		var contract map[string]any
		if err := json.Unmarshal(raw, &contract); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Contract Registered"),
			kvf("ID", getString(contract, "id")),
			kvf("Address", getString(contract, "address")),
			kvf("Name", getString(contract, "name")),
		)
	})
}

type updateContractArgs struct {
	OrgID    string         `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address  string         `json:"address" jsonschema:"contract address (0x-prefixed, required)"`
	Name     string         `json:"name,omitempty" jsonschema:"new name"`
	Metadata map[string]any `json:"metadata,omitempty" jsonschema:"new metadata"`
}

func registerUpdateContract(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "update_contract",
		Description: "Update a contract's name or metadata.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args updateContractArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		body := map[string]any{}
		if args.Name != "" {
			body["name"] = args.Name
		}
		if args.Metadata != nil {
			body["metadata"] = args.Metadata
		}

		raw, err := client.put(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts/%s", args.OrgID, args.Address), body)
		if err != nil {
			return errorResult("updating contract: %v", err)
		}
		var contract map[string]any
		if err := json.Unmarshal(raw, &contract); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Contract Updated"),
			kvf("Address", getString(contract, "address")),
			kvf("Name", getString(contract, "name")),
		)
	})
}

type deleteContractArgs struct {
	OrgID        string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address      string `json:"address" jsonschema:"contract address (0x-prefixed, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerDeleteContract(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_contract",
		Description: "Delete a contract. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteContractArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}

		if args.ConfirmToken == "" {
			token := confirms.Request("delete_contract", map[string]any{"org_id": args.OrgID, "address": args.Address})
			return textResult(
				section("Confirm Delete Contract"),
				kvf("Address", args.Address),
				"",
				"This will delete the contract and all its grants.",
				"",
				kvf("Confirmation Token", token),
				"Call delete_contract again with this confirm_token to execute.",
			)
		}

		params, err := confirms.Validate(args.ConfirmToken, "delete_contract")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}

		_, err = client.del(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts/%s", confirmParam(params, "org_id"), confirmParam(params, "address")))
		if err != nil {
			return errorResult("deleting contract: %v", err)
		}
		return textResult(section("Contract Deleted"))
	})
}

func registerListGrants(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_grants",
		Description: "List access grants for a contract (which groups can access it and with what function restrictions).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getContractArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts/%s/grants", args.OrgID, args.Address))
		if err != nil {
			return errorResult("listing grants: %v", err)
		}
		var grants []any
		if err := json.Unmarshal(raw, &grants); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Contract Grants for " + args.Address) + "\n"

		if len(grants) == 0 {
			lines += "No grants configured."
			return textResult(lines)
		}

		for _, g := range grants {
			grant, ok := g.(map[string]any)
			if !ok {
				continue
			}
			funcs := getSlice(grant, "functions")
			funcDesc := "all functions"
			if funcs != nil {
				funcDesc = fmt.Sprintf("%d specific functions", len(funcs))
			}
			lines += joinLines(
				"",
				kvf("Grant ID", getString(grant, "id")),
				kvf("Group ID", getString(grant, "group_id")),
				kvf("Functions", funcDesc),
			) + "\n"
		}
		return textResult(lines)
	})
}

type createGrantArgs struct {
	OrgID   string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address string `json:"address" jsonschema:"contract address (0x-prefixed, required)"`
	GroupID string `json:"group_id" jsonschema:"group to grant access to (UUID, required)"`
}

func registerCreateGrant(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_grant",
		Description: "Grant a group access to a contract (all functions by default).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args createGrantArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" || args.GroupID == "" {
			return errorResult("org_id, address, and group_id are required")
		}
		raw, err := client.post(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts/%s/grants", args.OrgID, args.Address), map[string]any{
			"group_id": args.GroupID,
		})
		if err != nil {
			return errorResult("creating grant: %v", err)
		}
		var grant map[string]any
		if err := json.Unmarshal(raw, &grant); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Grant Created"),
			kvf("Grant ID", getString(grant, "id")),
			kvf("Group ID", getString(grant, "group_id")),
			kvf("Contract", args.Address),
		)
	})
}

type deleteGrantArgs struct {
	OrgID        string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address      string `json:"address" jsonschema:"contract address (0x-prefixed, required)"`
	GroupID      string `json:"group_id" jsonschema:"group to revoke access from (UUID, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerDeleteGrant(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_grant",
		Description: "Revoke a group's access to a contract. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteGrantArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" || args.GroupID == "" {
			return errorResult("org_id, address, and group_id are required")
		}

		if args.ConfirmToken == "" {
			token := confirms.Request("delete_grant", map[string]any{
				"org_id": args.OrgID, "address": args.Address, "group_id": args.GroupID,
			})
			return textResult(
				section("Confirm Revoke Grant"),
				kvf("Contract", args.Address),
				kvf("Group ID", args.GroupID),
				"",
				kvf("Confirmation Token", token),
				"Call delete_grant again with this confirm_token to execute.",
			)
		}

		params, err := confirms.Validate(args.ConfirmToken, "delete_grant")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}

		_, err = client.del(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts/%s/grants/%s",
			confirmParam(params, "org_id"), confirmParam(params, "address"), confirmParam(params, "group_id")))
		if err != nil {
			return errorResult("revoking grant: %v", err)
		}
		return textResult(section("Grant Revoked"))
	})
}

type lookupContractArgs struct {
	Address string `json:"address" jsonschema:"contract address to look up globally (0x-prefixed, required)"`
}

func registerLookupContract(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "lookup_contract",
		Description: "Look up a contract by address across all organizations. Returns contract details, org, and all grants.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args lookupContractArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		raw, err := client.get("/api/v1/admin/contracts/by-address/" + args.Address)
		if err != nil {
			return errorResult("looking up contract: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}

		contract := getMap(resp, "contract")
		org := getMap(resp, "organization")
		grants := getSlice(resp, "grants")

		lines := section("Contract Lookup: " + args.Address) + "\n"
		if contract != nil {
			lines += joinLines(
				kvf("Name", getString(contract, "name")),
				kvf("Organization", getString(org, "name")),
				kvf("Org ID", getString(org, "id")),
			) + "\n"
		}

		if len(grants) > 0 {
			lines += "\n### Grants\n"
			for _, g := range grants {
				entry, ok := g.(map[string]any)
				if !ok {
					continue
				}
				group := getMap(entry, "group")
				lines += joinLines(
					kvf("Group", getString(group, "name")),
					kvf("Group ID", getString(group, "id")),
				) + "\n"
			}
		}
		return textResult(lines)
	})
}

type grantSummaryArgs struct {
	OrgID string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
}

func registerGrantSummary(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "grant_summary",
		Description: "Get an overview of contract grants across an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args grantSummaryArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/contracts/grant-summary", args.OrgID))
		if err != nil {
			return errorResult("getting grant summary: %v", err)
		}
		return textResult(section("Grant Summary"), prettyJSON(json.RawMessage(raw)))
	})
}
