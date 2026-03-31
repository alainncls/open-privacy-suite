package explorer

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// VisibilityLevel represents how much of an address's data is visible
type VisibilityLevel string

const (
	VisibilityFull         VisibilityLevel = "full"
	VisibilityPseudonymous VisibilityLevel = "pseudonymous"
	VisibilityRedacted     VisibilityLevel = "redacted"
	VisibilityHidden       VisibilityLevel = "hidden"
)

// VisibilityReason explains why an address has certain visibility
type VisibilityReason string

const (
	ReasonOwnAddress          VisibilityReason = "own_address"
	ReasonDisclosureGrant     VisibilityReason = "disclosure_grant"
	ReasonPublicAddress       VisibilityReason = "public_address"
	ReasonNoAccess            VisibilityReason = "no_access"
	ReasonRBACGroupMember     VisibilityReason = "rbac_group_member"
	ReasonParticipantOverride VisibilityReason = "participant_override"
)

// AddressVisibility represents the visibility status of a single address
type AddressVisibility struct {
	Address   string           `json:"address"`
	Visible   bool             `json:"visible"`
	Level     VisibilityLevel  `json:"level"`
	Reason    VisibilityReason `json:"reason"`
	Pseudonym *string          `json:"pseudonym,omitempty"`
	GrantID   *string          `json:"grant_id,omitempty"`
	ExpiresAt *time.Time       `json:"expires_at,omitempty"`
}

// GeneratePseudonym creates a consistent pseudonym for an address.
// Uses the first 4 hex digits of the address (after 0x prefix), mapping each
// hex digit (0-F) to a letter (A-P) to produce a human-readable identifier
// that does not expose raw hex characters.
func GeneratePseudonym(address string) string {
	addr := strings.ToLower(strings.TrimPrefix(strings.ToLower(address), "0x"))
	if len(addr) < 4 {
		return "Address-Unknown"
	}
	letters := make([]byte, 4)
	for i := 0; i < 4; i++ {
		c := addr[i]
		var digit byte
		if c >= '0' && c <= '9' {
			digit = c - '0'
		} else if c >= 'a' && c <= 'f' {
			digit = c - 'a' + 10
		} else {
			return "Address-Unknown"
		}
		letters[i] = 'A' + digit
	}
	return "Address-" + string(letters)
}

// GenerateAddressID creates an opaque identifier for an address that can be used for routing.
// The ID is derived from the address and grant ID to be unique per grant.
// SECURITY: This allows routing without revealing the real address.
func GenerateAddressID(address string, grantID string) string {
	data := strings.ToLower(address) + ":" + grantID
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // 16 hex chars
}
