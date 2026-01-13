package access

import (
	"errors"
	"testing"

	"privacy-proxy/internal/db"
)

// mockPolicyStore is a mock implementation of PolicyStore for testing
type mockPolicyStore struct {
	policies map[string]*db.AccessPolicy
	getError error
}

func newMockPolicyStore() *mockPolicyStore {
	return &mockPolicyStore{
		policies: make(map[string]*db.AccessPolicy),
	}
}

func (m *mockPolicyStore) GetPolicy(externalID string) (*db.AccessPolicy, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	return m.policies[externalID], nil
}

func (m *mockPolicyStore) SetPolicy(policy *db.AccessPolicy) error {
	if m.policies == nil {
		m.policies = make(map[string]*db.AccessPolicy)
	}
	m.policies[policy.ExternalID] = policy
	return nil
}

func (m *mockPolicyStore) ListPolicies() ([]*db.AccessPolicy, error) {
	policies := make([]*db.AccessPolicy, 0, len(m.policies))
	for _, p := range m.policies {
		policies = append(policies, p)
	}
	return policies, nil
}

func (m *mockPolicyStore) DeletePolicy(externalID string) error {
	delete(m.policies, externalID)
	return nil
}

func TestCheckAccess(t *testing.T) {
	mockStore := newMockPolicyStore()
	ctrl := NewController(mockStore)

	// Create a test policy
	policy := &db.AccessPolicy{
		ExternalID:   "billions:user_123",
		KYC:          true,
		AllowMethods: []string{"eth_call", "eth_getBalance"},
		Banned:       false,
	}
	mockStore.SetPolicy(policy)

	tests := []struct {
		name       string
		externalID string
		method     string
		wantErr    bool
	}{
		{
			name:       "allowed method",
			externalID: "billions:user_123",
			method:     "eth_call",
			wantErr:    false,
		},
		{
			name:       "another allowed method",
			externalID: "billions:user_123",
			method:     "eth_getBalance",
			wantErr:    false,
		},
		{
			name:       "disallowed method",
			externalID: "billions:user_123",
			method:     "eth_sendTransaction",
			wantErr:    true,
		},
		{
			name:       "non-existent user",
			externalID: "billions:unknown",
			method:     "eth_call",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ctrl.CheckAccess(tt.externalID, tt.method)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCheckAccess_Banned(t *testing.T) {
	mockStore := newMockPolicyStore()
	ctrl := NewController(mockStore)

	// Create a banned policy
	policy := &db.AccessPolicy{
		ExternalID:   "billions:banned_user",
		KYC:          true,
		AllowMethods: []string{"eth_call"},
		Banned:       true,
	}
	mockStore.SetPolicy(policy)

	err := ctrl.CheckAccess("billions:banned_user", "eth_call")
	if err == nil {
		t.Errorf("expected error for banned user but got none")
	}
}

func TestCheckAccess_KYCRequired(t *testing.T) {
	mockStore := newMockPolicyStore()
	ctrl := NewController(mockStore)

	// Create a policy without KYC
	policy := &db.AccessPolicy{
		ExternalID:   "billions:no_kyc_user",
		KYC:          false,
		AllowMethods: []string{"eth_call"},
		Banned:       false,
	}
	mockStore.SetPolicy(policy)

	err := ctrl.CheckAccess("billions:no_kyc_user", "eth_call")
	if err == nil {
		t.Errorf("expected error for non-KYC user but got none")
	}

	if err != nil && err.Error() != "KYC required for billions:no_kyc_user" {
		t.Errorf("expected KYC error, got: %v", err)
	}
}

func TestCheckAccess_DatabaseError(t *testing.T) {
	mockStore := newMockPolicyStore()
	mockStore.getError = errors.New("database connection failed")
	ctrl := NewController(mockStore)

	err := ctrl.CheckAccess("billions:user_123", "eth_call")
	if err == nil {
		t.Errorf("expected error for database failure but got none")
	}
}
