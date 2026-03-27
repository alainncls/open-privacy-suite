package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// WebhookNotifier sends HTTP POST requests for governance events.
type WebhookNotifier struct {
	client *http.Client
	db     *db.DB
}

// NewWebhookNotifier creates a new notifier with SSRF protection.
func NewWebhookNotifier(database *db.DB) *WebhookNotifier {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
					return nil, fmt.Errorf("SSRF protection: access to restricted IP %s is denied", ip.String())
				}
			}
			return net.DialTimeout(network, net.JoinHostPort(ips[0].String(), port), 3*time.Second)
		},
	}
	return &WebhookNotifier{
		client: &http.Client{Transport: transport, Timeout: 10 * time.Second},
		db:     database,
	}
}

type webhookPayload struct {
	Event   string                `json:"event"`
	Request *rbac.ApprovalRequest `json:"request"`
}

// NotifyNewRequest sends a webhook when a new request is created.
func (n *WebhookNotifier) NotifyNewRequest(ctx context.Context, req *rbac.ApprovalRequest) error {
	org, err := n.db.GetOrganization(ctx, req.OrgID)
	if err != nil || org == nil || org.GovernanceWebhookURL == nil || *org.GovernanceWebhookURL == "" {
		return nil
	}

	payload := webhookPayload{Event: "new_approval_request", Request: req}
	data, _ := json.Marshal(payload)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", *org.GovernanceWebhookURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Call asynchronously from the engine, or run it here async?
	// It's better to NOT block the main HTTP thread.
	go func() {
		// Use a detached background context instead of the request context
		// because the request context cancels as soon as the HTTP handler returns.
		reqCopy, _ := http.NewRequestWithContext(context.Background(), "POST", *org.GovernanceWebhookURL, bytes.NewReader(data))
		reqCopy.Header.Set("Content-Type", "application/json")

		resp, err := n.client.Do(reqCopy)
		if err == nil {
			resp.Body.Close()
		}
	}()

	return nil
}

// NotifyEscalation sends a webhook when a request is escalated.
func (n *WebhookNotifier) NotifyEscalation(ctx context.Context, req *rbac.ApprovalRequest) error {
	org, err := n.db.GetOrganization(ctx, req.OrgID)
	if err != nil || org == nil || org.GovernanceWebhookURL == nil || *org.GovernanceWebhookURL == "" {
		return nil
	}

	payload := webhookPayload{Event: "request_escalated", Request: req}
	data, _ := json.Marshal(payload)

	reqCopy, err := http.NewRequestWithContext(context.Background(), "POST", *org.GovernanceWebhookURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	reqCopy.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(reqCopy)
	if err == nil {
		resp.Body.Close()
	}
	return err
}
