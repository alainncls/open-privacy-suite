package main

import "context"

type CallerInfo struct {
	ID    string
	Name  string
	Roles []string
}

type AuthManager interface {
	CallerIdentity(ctx context.Context) (*CallerInfo, error)
	CanUseTool(ctx context.Context, caller *CallerInfo, toolName string) error
	UpstreamAuth(ctx context.Context, caller *CallerInfo) (string, error)
}

type StaticAdminAuth struct {
	token string
}

func NewStaticAdminAuth(token string) *StaticAdminAuth {
	return &StaticAdminAuth{token: token}
}

func (a *StaticAdminAuth) CallerIdentity(_ context.Context) (*CallerInfo, error) {
	return &CallerInfo{ID: "admin", Name: "admin", Roles: []string{"admin"}}, nil
}

func (a *StaticAdminAuth) CanUseTool(_ context.Context, _ *CallerInfo, _ string) error {
	return nil
}

func (a *StaticAdminAuth) UpstreamAuth(_ context.Context, _ *CallerInfo) (string, error) {
	return a.token, nil
}
