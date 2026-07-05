package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// #452 follow-up: RecordLoginAttempt/CountRecentLoginAttempts/PruneLoginAttempts now
// have a REAL server endpoint to proxy to, closing the gap two earlier rounds (#452,
// #454) deliberately left open pending further investigation — "a real proxied atomic
// endpoint was evaluated and rejected as out of scope". That evaluation assumed the
// upstream server would need a NEW authorization model for a system-to-system caller;
// in fact the upstream API a RemoteStorage client already authenticates against (every
// other remote_*.go call — CreateUser, DeleteUser, full secret CRUD, ...) requires a
// credential with FAR broader privilege than "record/count an IP's recent login
// attempts" would ever need, so gating these three new endpoints behind the same
// existing system.read/system.write RBAC permissions (server/http/router.go's
// /api/v1/system/login-attempts routes) introduces no new privilege class at all.
//
// These proxy directly onto the upstream's own login_attempts table/storage.Storage
// primitives (ADR-040) — the SAME table the upstream's own /auth/login handler uses
// for its own direct end-user traffic, and the SAME one password-reset rate limiting
// already reuses via the "pwreset:" key prefix (internal/core/rate_limit.go). A
// downstream server's forwarded IP therefore shares one cluster-wide budget per key
// with the upstream's own direct traffic for that same key — the correct behavior
// (the same abusive client IP hitting either front door is the same abuse), not a
// conflation of unrelated data.
func (rs *RemoteStorage) RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error {
	body := struct {
		IP string    `json:"ip"`
		At time.Time `json:"at"`
	}{IP: ip, At: at}
	resp, err := rs.client.Post(ctx, "/api/v1/system/login-attempts", body)
	if err != nil {
		return fmt.Errorf("failed to record login attempt: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("record login attempt failed: %s", resp.Error.Error())
	}
	return nil
}

func (rs *RemoteStorage) CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error) {
	q := url.Values{}
	q.Set("ip", ip)
	q.Set("since", since.UTC().Format(time.RFC3339Nano))
	path := "/api/v1/system/login-attempts/count?" + q.Encode()

	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("failed to count login attempts: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("count login attempts failed: %s", resp.Error.Error())
	}
	var result struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Count, nil
}

func (rs *RemoteStorage) PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error) {
	body := struct {
		Before time.Time `json:"before"`
	}{Before: before}
	resp, err := rs.client.Post(ctx, "/api/v1/system/login-attempts/prune", body)
	if err != nil {
		return 0, fmt.Errorf("failed to prune login attempts: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("prune login attempts failed: %s", resp.Error.Error())
	}
	var result struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Deleted, nil
}
