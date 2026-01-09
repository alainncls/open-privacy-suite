package identity

import (
	"testing"
)

func TestResolveIdentity(t *testing.T) {
	svc := NewService("http://localhost:9000")
	
	tests := []struct {
		name     string
		token    string
		wantErr  bool
		checkID  func(*Identity) bool
	}{
		{
			name:    "valid token",
			token:   "user_123",
			wantErr: false,
			checkID: func(id *Identity) bool {
				return id.Subject == "billions:user_123" && id.KYC == true
			},
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "another valid token",
			token:   "test_user",
			wantErr: false,
			checkID: func(id *Identity) bool {
				return id.Subject == "billions:test_user"
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := svc.ResolveIdentity(tt.token)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if identity == nil {
				t.Errorf("expected identity but got nil")
				return
			}
			
			if tt.checkID != nil && !tt.checkID(identity) {
				t.Errorf("identity validation failed")
			}
		})
	}
}
