package server

// Spec-only request/response mirror structs for the RBAC-core admin handlers
// (RD-1166).
//
// These types exist ONLY so the swaggo (@Param/@Success) annotations on
// handlers that bind or respond with a gin.H / anonymous shape have a concrete
// Go type to point at. They are never constructed at runtime — annotation
// references only, and
// they must stay byte-for-byte faithful to the wire shape the handler emits
// (same JSON keys, same element types). Handlers that already respond with a
// named, exported Go struct (own package, rbac.X, db.X) reference that struct
// directly and need no mirror here.
//
// This file must compile standalone with the imports the package already has;
// it introduces no new imports. Element types are referenced from their real
// definitions (internal/rbac, internal/db, and same-package types such as
// userListItem) so the documented shape can never silently drift from them.

import (
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// AuditLogEntryDoc re-declares rbac.AuditLogEntry for the OpenAPI annotations
// in admin_rbac_audit.go: swag resolves annotation types through the imports
// of the file the annotation lives in, and that file does not (and need not)
// import rbac. Same underlying type — fields can never drift.
type AuditLogEntryDoc rbac.AuditLogEntry

// orgListResponse is the GET /api/v1/admin/orgs body: a page of organizations
// plus the pagination echo. Emitted via gin.H{"data","total","limit","offset"}.
type orgListResponse struct {
	Data   []*rbac.Organization `json:"data"`
	Total  int                  `json:"total" example:"1"`
	Limit  int                  `json:"limit" example:"50"`
	Offset int                  `json:"offset" example:"0"`
}

// groupListResponse is the GET /api/v1/admin/orgs/{org_id}/groups body: a page
// of groups (each with its access settings) plus the pagination echo.
type groupListResponse struct {
	Data   []rbac.GroupWithAccess `json:"data"`
	Total  int                    `json:"total" example:"1"`
	Limit  int                    `json:"limit" example:"50"`
	Offset int                    `json:"offset" example:"0"`
}

// groupBatchDeletePreviewEntry mirrors one entry of the batch-delete-preview
// response. It matches the handler's local groupPreview struct exactly: the
// counts and the affected contract addresses that a delete would cascade.
type groupBatchDeletePreviewEntry struct {
	ID            string   `json:"id" example:"6f1e2d3c-0000-0000-0000-000000000001"`
	Name          string   `json:"name" example:"engineering"`
	Slug          string   `json:"slug" example:"engineering"`
	ContractCount int      `json:"contract_count" example:"2"`
	MemberCount   int      `json:"member_count" example:"5"`
	Contracts     []string `json:"contracts"` // contract addresses
}

// groupBatchDeletePreviewResponse is the POST
// /api/v1/admin/orgs/{org_id}/groups/batch-delete-preview body.
type groupBatchDeletePreviewResponse struct {
	Groups []groupBatchDeletePreviewEntry `json:"groups"`
}

// groupBatchDeleteResponse is the POST
// /api/v1/admin/orgs/{org_id}/groups/batch-delete body: the number of groups
// deleted in the atomic batch.
type groupBatchDeleteResponse struct {
	DeletedCount int `json:"deleted_count" example:"3"`
}

// userListResponse is the GET /api/v1/admin/users body: a page of users (each
// with a scoped memberships summary) plus the pagination echo. The element type
// is the handler's own userListItem (rbac.User fields plus the groups column).
type userListResponse struct {
	Data   []userListItem `json:"data"`
	Total  int            `json:"total" example:"1"`
	Limit  int            `json:"limit" example:"50"`
	Offset int            `json:"offset" example:"0"`
}

// linkedAddressEntry mirrors one linked-ETH-address row of the
// GET /api/v1/admin/users/{user_id}/linked-addresses response. It matches the
// handler's local AddressResponse shape.
type linkedAddressEntry struct {
	Address       string  `json:"address" example:"0x0000000000000000000000000000000000000001"`
	VerifiedAt    string  `json:"verified_at" example:"2026-01-01T00:00:00Z"`
	ENSName       *string `json:"ens_name,omitempty" example:"alice.eth"`
	ENSResolvedAt *string `json:"ens_resolved_at,omitempty" example:"2026-01-01T00:00:00Z"`
}

// userLinkedAddressesResponse is the GET
// /api/v1/admin/users/{user_id}/linked-addresses body.
type userLinkedAddressesResponse struct {
	Addresses []linkedAddressEntry `json:"addresses"`
}

// membershipByDIDResponse is the POST
// /api/v1/admin/orgs/{org_id}/memberships/by-did body: the resolved (or freshly
// provisioned) internal user ID plus the membership row that was created.
type membershipByDIDResponse struct {
	UserID     string               `json:"user_id" example:"6f1e2d3c-0000-0000-0000-000000000002"`
	Membership *rbac.UserMembership `json:"membership"`
}

// ethAddressCollisionsResponse is the GET
// /api/v1/admin/eth-addresses/collisions body: ETH addresses linked to more
// than one DID, plus the count of collisions in the (possibly scoped) result.
type ethAddressCollisionsResponse struct {
	Collisions []*db.AddressLinkCollision `json:"collisions"`
	Count      int                        `json:"count" example:"0"`
}

// ---- Request-body mirrors ---------------------------------------------
//
// The handlers below bind inline anonymous structs, which swaggo cannot
// reference by name; these mirrors reproduce them field-for-field (same JSON
// keys, same types, same binding:"required" markers — swag turns the binding
// tag into the OpenAPI required list). Never bound at runtime.

// orgCreateRequest is the POST /api/v1/admin/orgs body.
type orgCreateRequest struct {
	Slug     string         `json:"slug" binding:"required" example:"acme"`
	Name     string         `json:"name" binding:"required" example:"ACME Corp"`
	Settings map[string]any `json:"settings"`
}

// orgUpdateRequest is the PUT /api/v1/admin/orgs/{org_id} body; all fields
// optional, only supplied fields change.
type orgUpdateRequest struct {
	Slug     *string        `json:"slug" example:"acme"`
	Name     *string        `json:"name" example:"ACME Corp"`
	Settings map[string]any `json:"settings"`
}

// groupCreateRequest is the POST /api/v1/admin/orgs/{org_id}/groups body.
type groupCreateRequest struct {
	Slug               string  `json:"slug" binding:"required" example:"engineering"`
	Name               string  `json:"name" binding:"required" example:"Engineering"`
	Description        string  `json:"description"`
	ParentID           *string `json:"parent_id" example:"6f1e2d3c-0000-0000-0000-000000000001"`
	IsOrgAdmin         bool    `json:"is_org_admin"`
	IsOrgReadonlyAdmin bool    `json:"is_org_readonly_admin"`
}

// groupUpdateRequest is the PUT /api/v1/admin/orgs/{org_id}/groups/{group_id}
// body; all fields optional.
type groupUpdateRequest struct {
	Name               *string `json:"name"`
	Description        *string `json:"description"`
	IsOrgAdmin         *bool   `json:"is_org_admin"`
	IsOrgReadonlyAdmin *bool   `json:"is_org_readonly_admin"`
}

// groupAccessRequest is the PUT
// /api/v1/admin/orgs/{org_id}/groups/{group_id}/access body.
type groupAccessRequest struct {
	AllowedMethods []string     `json:"allowed_methods"`
	Claims         []rbac.Claim `json:"claims"`
	RateLimitRPS   *int         `json:"rate_limit_rps" example:"50"`
	RateLimitDaily *int         `json:"rate_limit_daily" example:"100000"`
	RPCAPIKey      *string      `json:"rpc_api_key"`
	VerboseErrors  bool         `json:"verbose_errors"`
}

// groupBatchDeleteRequest is the body of both
// POST .../groups/batch-delete-preview and POST .../groups/batch-delete.
type groupBatchDeleteRequest struct {
	GroupIDs []string `json:"group_ids" binding:"required"`
}

// rbacUserUpdateRequest is the PUT /api/v1/admin/users/{user_id} body; all
// fields optional.
type rbacUserUpdateRequest struct {
	KYC      *bool          `json:"kyc"`
	Banned   *bool          `json:"banned"`
	Note     *string        `json:"note"`
	Metadata map[string]any `json:"metadata"`
}

// membershipCreateRequest is the POST
// /api/v1/admin/users/{user_id}/memberships body. ExpiresAt is an optional
// RFC3339 expiry for a time-boxed access window (RD-1145).
type membershipCreateRequest struct {
	GroupID   string  `json:"group_id" binding:"required" example:"6f1e2d3c-0000-0000-0000-000000000001"`
	ExpiresAt *string `json:"expires_at" example:"2027-01-01T00:00:00Z"`
}

// membershipByDIDRequest is the POST
// /api/v1/admin/orgs/{org_id}/memberships/by-did body. ExpiresAt is an
// optional RFC3339 expiry for a time-boxed access window (RD-1145).
type membershipByDIDRequest struct {
	DID       string  `json:"did" binding:"required" example:"did:example:alice"`
	GroupID   string  `json:"group_id" binding:"required" example:"6f1e2d3c-0000-0000-0000-000000000001"`
	ExpiresAt *string `json:"expires_at" example:"2027-01-01T00:00:00Z"`
}
