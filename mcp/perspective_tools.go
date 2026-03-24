package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerPerspectiveTools(s *mcp.Server, client *httpClient) {
	registerSetPerspective(s, client)
	registerClearPerspective(s, client)
	registerWhoAmI(s, client)
	registerWhatCanUserSee(s, client)
}

type setPerspectiveArgs struct {
	Query string `json:"query" jsonschema:"user to act as — DID, ETH address, or user ID (required)"`
	Level int    `json:"level,omitempty" jsonschema:"perspective level: use 1 for read-only reporting (default) or 2 for full impersonation (requires API support)"`
}

func registerSetPerspective(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_perspective",
		Description: "Set perspective to view the system as a specific user. Level 1 (default): read-only, queries permissions and presents filtered views. Level 2: full impersonation via X-Impersonate-User header (requires API support).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args setPerspectiveArgs) (*mcp.CallToolResult, any, error) {
		if args.Query == "" {
			return errorResult("query is required — provide a DID, ETH address, or user ID")
		}

		level := args.Level
		if level == 0 {
			level = 1
		}
		if level != 1 && level != 2 {
			return errorResult("level must be 1 (read-only) or 2 (impersonation)")
		}

		// Try direct user ID first
		userID := args.Query
		userName := args.Query

		raw, err := client.get("/api/v1/admin/users/" + args.Query)
		if err != nil {
			// Not a direct ID — search
			raw, err = client.get("/api/v1/admin/users?search=" + args.Query + "&limit=5")
			if err != nil {
				return errorResult("searching users: %v", err)
			}
			var resp map[string]any
			json.Unmarshal(raw, &resp)
			users := getSlice(resp, "data")

			if len(users) == 0 {
				return errorResult("no user found matching %q", args.Query)
			}
			if len(users) > 1 {
				lines := fmt.Sprintf("## Multiple users match %q — be more specific\n", args.Query)
				for _, u := range users {
					user, ok := u.(map[string]any)
					if !ok {
						continue
					}
					lines += joinLines(
						kvf("ID", getString(user, "id")),
						kvf("DID", getString(user, "external_id")),
					) + "\n"
				}
				return textResult(lines)
			}

			user := users[0].(map[string]any)
			userID = getString(user, "id")
			userName = getString(user, "external_id")
			if userName == "" {
				userName = userID
			}
		} else {
			var user map[string]any
			json.Unmarshal(raw, &user)
			userID = getString(user, "id")
			did := getString(user, "external_id")
			if did != "" {
				userName = did
			}
		}

		client.perspective = &Perspective{
			Active:   true,
			UserID:   userID,
			UserName: userName,
			Level:    level,
		}

		lines := section("Perspective Set") + "\n"
		lines += joinLines(
			kvf("User ID", userID),
			kvf("User", userName),
			kvf("Level", fmt.Sprintf("%d — %s", level, perspectiveLevelDesc(level))),
		)
		if level == 1 {
			lines += "\n\nAll queries will show this user's view (approximate — based on permission query, not actual API enforcement)."
		} else {
			lines += "\n\nAll API calls will use X-Impersonate-User header. Audit log records both your identity and the impersonated user."
		}

		return textResult(lines)
	})
}

func registerClearPerspective(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "clear_perspective",
		Description: "Return to admin view. Removes any active user perspective.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		prev := client.perspective
		client.perspective = nil

		if prev == nil || !prev.Active {
			return textResult(section("No Perspective Active"), "Already viewing as admin.")
		}

		return textResult(
			section("Perspective Cleared"),
			fmt.Sprintf("Returned to admin view. Was viewing as: %s", prev.UserName),
		)
	})
}

func registerWhoAmI(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "who_am_i",
		Description: "Show the current perspective: admin view or acting as a specific user.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		p := client.perspective
		if p == nil || !p.Active {
			return textResult(
				section("Current Perspective: Admin"),
				"Viewing as admin. All tools return full data.",
			)
		}
		return textResult(
			section("Current Perspective: "+p.UserName),
			kvf("User ID", p.UserID),
			kvf("Level", fmt.Sprintf("%d — %s", p.Level, perspectiveLevelDesc(p.Level))),
			"",
			"Use clear_perspective to return to admin view.",
		)
	})
}

type whatCanUserSeeArgs struct {
	UserID string `json:"user_id" jsonschema:"user ID (UUID, required)"`
	Org    string `json:"org,omitempty" jsonschema:"organization slug (default: 'default')"`
}

func registerWhatCanUserSee(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "what_can_user_see",
		Description: "Composite query: get a complete view of what a user can access across all three layers — RPC methods, contract access, and explorer visibility. Also shows linked addresses and group memberships.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args whatCanUserSeeArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" {
			return errorResult("user_id is required")
		}

		lines := section("What Can This User See?") + "\n"

		// 1. User info
		raw, err := client.get("/api/v1/admin/users/" + args.UserID)
		if err != nil {
			return errorResult("getting user: %v", err)
		}
		var user map[string]any
		json.Unmarshal(raw, &user)
		lines += joinLines(
			kvf("User ID", getString(user, "id")),
			kvf("DID", getString(user, "external_id")),
			kvf("Banned", boolYesNo(getBool(user, "banned"))),
		) + "\n"

		// 2. Linked addresses
		raw, err = client.get("/api/v1/admin/users/" + args.UserID + "/linked-addresses")
		if err == nil {
			var addrResp map[string]any
			json.Unmarshal(raw, &addrResp)
			addrs := getSlice(addrResp, "addresses")
			lines += "\n### Linked Addresses\n"
			if len(addrs) == 0 {
				lines += "None\n"
			}
			for _, a := range addrs {
				addr, ok := a.(map[string]any)
				if !ok {
					continue
				}
				ens := getString(addr, "ens_name")
				if ens != "" {
					ens = " (" + ens + ")"
				}
				lines += fmt.Sprintf("- %s%s\n", getString(addr, "address"), ens)
			}
		}

		// 3. Memberships
		raw, err = client.get("/api/v1/admin/users/" + args.UserID + "/memberships")
		if err == nil {
			var memberships []any
			json.Unmarshal(raw, &memberships)
			lines += "\n### Group Memberships\n"
			if len(memberships) == 0 {
				lines += "None\n"
			}
			for _, m := range memberships {
				entry, ok := m.(map[string]any)
				if !ok {
					continue
				}
				group := getMap(entry, "group")
				if group != nil {
					admin := ""
					if getBool(group, "is_org_admin") {
						admin = " (ORG ADMIN)"
					}
					lines += fmt.Sprintf("- %s [%s]%s\n", getString(group, "name"), getString(group, "path"), admin)
				}
			}
		}

		// 4. Effective permissions
		permPath := "/api/v1/admin/users/" + args.UserID + "/effective-permissions"
		if args.Org != "" {
			permPath += "?org=" + args.Org
		}
		raw, err = client.get(permPath)
		if err == nil {
			var perms map[string]any
			json.Unmarshal(raw, &perms)

			lines += "\n### RPC Method Access\n"
			methods := getSlice(perms, "allowed_methods")
			if len(methods) == 0 {
				lines += "None\n"
			} else {
				for _, m := range methods {
					lines += fmt.Sprintf("- %v\n", m)
				}
			}

			lines += "\n### Claims\n"
			claims := getSlice(perms, "claims")
			if len(claims) == 0 {
				lines += "None\n"
			} else {
				for _, c := range claims {
					lines += fmt.Sprintf("- %v\n", c)
				}
			}

			if rps := perms["rate_limit_rps"]; rps != nil {
				lines += "\n" + kvf("Rate Limit RPS", rps) + "\n"
			}

			contracts := getMap(perms, "contract_access")
			if len(contracts) > 0 {
				lines += "\n### Contract Access\n"
				for addr, v := range contracts {
					ca, ok := v.(map[string]any)
					if !ok {
						continue
					}
					lines += fmt.Sprintf("- **%s**: claims=%v\n", addr, getSlice(ca, "claims"))
				}
			} else {
				lines += "\n### Contract Access\nNo contract-specific access\n"
			}
		}

		return textResult(lines)
	})
}

func perspectiveLevelDesc(level int) string {
	switch level {
	case 2:
		return "full impersonation"
	default:
		return "read-only reporting"
	}
}
