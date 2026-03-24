package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerGroupTools(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	registerListGroups(s, client)
	registerGetGroup(s, client)
	registerCreateGroup(s, client)
	registerUpdateGroup(s, client)
	registerDeleteGroup(s, client, confirms)
	registerGetGroupAccess(s, client)
	registerSetGroupAccess(s, client)
}

type listGroupsArgs struct {
	OrgID  string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max entries (default 50)"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
}

func registerListGroups(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_groups",
		Description: "List groups in an organization with their access permissions.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listGroupsArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		limit := args.Limit
		if limit == 0 {
			limit = 50
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/groups?limit=%d&offset=%d", args.OrgID, limit, args.Offset))
		if err != nil {
			return errorResult("listing groups: %v", err)
		}
		var resp map[string]any
		json.Unmarshal(raw, &resp)

		items := getSlice(resp, "data")
		lines := section("Groups") + "\n"
		lines += kvf("Total", getFloat(resp, "total")) + "\n"

		for _, item := range items {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			group := getMap(entry, "group")
			access := getMap(entry, "access")
			if group == nil {
				continue
			}

			lines += fmt.Sprintf("\n### %s\n", getString(group, "name"))
			lines += joinLines(
				kvf("ID", getString(group, "id")),
				kvf("Slug", getString(group, "slug")),
				kvf("Path", getString(group, "path")),
				kvf("Depth", getFloat(group, "depth")),
				kvf("Org Admin", boolYesNo(getBool(group, "is_org_admin"))),
			)

			if access != nil {
				claims := getSlice(access, "claims")
				methods := getSlice(access, "allowed_methods")
				lines += "\n" + joinLines(
					kvf("Claims", fmt.Sprintf("%v", claims)),
					kvf("Allowed Methods", fmt.Sprintf("%d methods", len(methods))),
					kvf("Rate Limit RPS", access["rate_limit_rps"]),
				)
			}
			lines += "\n"
		}
		return textResult(lines)
	})
}

type getGroupArgs struct {
	OrgID   string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	GroupID string `json:"group_id" jsonschema:"group ID (UUID, required)"`
}

func registerGetGroup(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_group",
		Description: "Get details of a specific group.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getGroupArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.GroupID == "" {
			return errorResult("org_id and group_id are required")
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/groups/%s", args.OrgID, args.GroupID))
		if err != nil {
			return errorResult("getting group: %v", err)
		}
		var group map[string]any
		json.Unmarshal(raw, &group)

		return textResult(
			section("Group: "+getString(group, "name")),
			kvf("ID", getString(group, "id")),
			kvf("Org ID", getString(group, "org_id")),
			kvf("Parent ID", getString(group, "parent_id")),
			kvf("Slug", getString(group, "slug")),
			kvf("Path", getString(group, "path")),
			kvf("Depth", getFloat(group, "depth")),
			kvf("Description", getString(group, "description")),
			kvf("Org Admin", boolYesNo(getBool(group, "is_org_admin"))),
		)
	})
}

type createGroupArgs struct {
	OrgID       string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Slug        string `json:"slug" jsonschema:"URL-friendly identifier (required)"`
	Name        string `json:"name" jsonschema:"display name (required)"`
	Description string `json:"description,omitempty" jsonschema:"group description"`
	ParentID    string `json:"parent_id,omitempty" jsonschema:"parent group ID for nesting"`
	IsOrgAdmin  bool   `json:"is_org_admin,omitempty" jsonschema:"whether this group has org admin privileges"`
}

func registerCreateGroup(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_group",
		Description: "Create a new group in an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args createGroupArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Slug == "" || args.Name == "" {
			return errorResult("org_id, slug, and name are required")
		}
		body := map[string]any{
			"slug": args.Slug,
			"name": args.Name,
		}
		if args.Description != "" {
			body["description"] = args.Description
		}
		if args.ParentID != "" {
			body["parent_id"] = args.ParentID
		}
		if args.IsOrgAdmin {
			body["is_org_admin"] = true
		}

		raw, err := client.post(fmt.Sprintf("/api/v1/admin/orgs/%s/groups", args.OrgID), body)
		if err != nil {
			return errorResult("creating group: %v", err)
		}
		var group map[string]any
		json.Unmarshal(raw, &group)

		return textResult(
			section("Group Created"),
			kvf("ID", getString(group, "id")),
			kvf("Slug", getString(group, "slug")),
			kvf("Name", getString(group, "name")),
			kvf("Path", getString(group, "path")),
		)
	})
}

type updateGroupArgs struct {
	OrgID       string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	GroupID     string `json:"group_id" jsonschema:"group ID (UUID, required)"`
	Name        string `json:"name,omitempty" jsonschema:"new name"`
	Description string `json:"description,omitempty" jsonschema:"new description"`
	IsOrgAdmin  *bool  `json:"is_org_admin,omitempty" jsonschema:"set org admin status"`
}

func registerUpdateGroup(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "update_group",
		Description: "Update a group's name, description, or admin status.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args updateGroupArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.GroupID == "" {
			return errorResult("org_id and group_id are required")
		}
		body := map[string]any{}
		if args.Name != "" {
			body["name"] = args.Name
		}
		if args.Description != "" {
			body["description"] = args.Description
		}
		if args.IsOrgAdmin != nil {
			body["is_org_admin"] = *args.IsOrgAdmin
		}

		raw, err := client.put(fmt.Sprintf("/api/v1/admin/orgs/%s/groups/%s", args.OrgID, args.GroupID), body)
		if err != nil {
			return errorResult("updating group: %v", err)
		}
		var group map[string]any
		json.Unmarshal(raw, &group)

		return textResult(
			section("Group Updated"),
			kvf("ID", getString(group, "id")),
			kvf("Name", getString(group, "name")),
		)
	})
}

type deleteGroupArgs struct {
	OrgID        string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	GroupID      string `json:"group_id" jsonschema:"group ID (UUID, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerDeleteGroup(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_group",
		Description: "Delete a group. First call without confirm_token for preview, then with token to execute.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteGroupArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.GroupID == "" {
			return errorResult("org_id and group_id are required")
		}

		if args.ConfirmToken == "" {
			token := confirms.Request("delete_group", map[string]any{"org_id": args.OrgID, "group_id": args.GroupID})
			return textResult(
				section("Confirm Delete Group"),
				kvf("Group ID", args.GroupID),
				"",
				"This will permanently delete the group and remove all memberships.",
				"",
				kvf("Confirmation Token", token),
				"Call delete_group again with this confirm_token to execute.",
			)
		}

		params, err := confirms.Validate(args.ConfirmToken, "delete_group")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}

		_, err = client.del(fmt.Sprintf("/api/v1/admin/orgs/%s/groups/%s", params["org_id"], params["group_id"]))
		if err != nil {
			return errorResult("deleting group: %v", err)
		}
		return textResult(section("Group Deleted"))
	})
}

func registerGetGroupAccess(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_group_access",
		Description: "Get a group's access permissions: allowed RPC methods, claims, and rate limits.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getGroupArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.GroupID == "" {
			return errorResult("org_id and group_id are required")
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/admin/orgs/%s/groups/%s/access", args.OrgID, args.GroupID))
		if err != nil {
			return errorResult("getting group access: %v", err)
		}
		var access map[string]any
		json.Unmarshal(raw, &access)

		return textResult(
			section("Group Access"),
			kvf("Claims", fmt.Sprintf("%v", getSlice(access, "claims"))),
			kvf("Effective Claims", fmt.Sprintf("%v", getSlice(access, "effective_claims"))),
			kvf("Narrowed By Parent", boolYesNo(getBool(access, "narrowed_by_parent"))),
			kvf("Allowed Methods", fmt.Sprintf("%v", getSlice(access, "allowed_methods"))),
			kvf("Rate Limit RPS", access["rate_limit_rps"]),
			kvf("Rate Limit Daily", access["rate_limit_daily"]),
		)
	})
}

type setGroupAccessArgs struct {
	OrgID          string   `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	GroupID        string   `json:"group_id" jsonschema:"group ID (UUID, required)"`
	AllowedMethods []string `json:"allowed_methods" jsonschema:"list of allowed RPC methods (e.g. eth_call, eth_sendTransaction)"`
	Claims         []string `json:"claims" jsonschema:"permission claims (read, write, deploy, upgrade, admin)"`
	RateLimitRPS   *int     `json:"rate_limit_rps,omitempty" jsonschema:"requests per second limit"`
	RateLimitDaily *int     `json:"rate_limit_daily,omitempty" jsonschema:"daily request limit"`
}

func registerSetGroupAccess(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_group_access",
		Description: "Set a group's access permissions: allowed RPC methods, claims, and rate limits. Claims are auto-expanded (admin includes all).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args setGroupAccessArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.GroupID == "" {
			return errorResult("org_id and group_id are required")
		}
		body := map[string]any{
			"allowed_methods": args.AllowedMethods,
			"claims":          args.Claims,
		}
		if args.RateLimitRPS != nil {
			body["rate_limit_rps"] = *args.RateLimitRPS
		}
		if args.RateLimitDaily != nil {
			body["rate_limit_daily"] = *args.RateLimitDaily
		}

		raw, err := client.put(fmt.Sprintf("/api/v1/admin/orgs/%s/groups/%s/access", args.OrgID, args.GroupID), body)
		if err != nil {
			return errorResult("setting group access: %v", err)
		}
		var access map[string]any
		json.Unmarshal(raw, &access)

		return textResult(
			section("Group Access Updated"),
			kvf("Claims", fmt.Sprintf("%v", getSlice(access, "claims"))),
			kvf("Effective Claims", fmt.Sprintf("%v", getSlice(access, "effective_claims"))),
			kvf("Allowed Methods", fmt.Sprintf("%v", getSlice(access, "allowed_methods"))),
			kvf("Rate Limit RPS", access["rate_limit_rps"]),
		)
	})
}
