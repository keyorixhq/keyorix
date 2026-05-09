// remote_rotation_policies.go — RotationPolicy operations for RemoteStorage.
//
// Proxies all operations to the Keyorix REST API.
// For the local (GORM) equivalent see local_rotation_policies.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error {
	resp, err := rs.client.Post(ctx, "/api/v1/rotation-policies", p)
	if err != nil {
		return fmt.Errorf("failed to create rotation policy: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("create rotation policy failed: %s", resp.Error.Error())
	}
	var result models.RotationPolicy
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	*p = result
	return nil
}

func (rs *RemoteStorage) GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/rotation-policies/%d", id))
	if err != nil {
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get rotation policy failed: %s", resp.Error.Error())
	}
	var result models.RotationPolicy
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

func (rs *RemoteStorage) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	path := "/api/v1/rotation-policies"
	first := true
	appendParam := func(key string, val uint) {
		if first {
			path += fmt.Sprintf("?%s=%d", key, val)
			first = false
		} else {
			path += fmt.Sprintf("&%s=%d", key, val)
		}
	}
	if projectID != nil {
		appendParam("project_id", *projectID)
	}
	if environmentID != nil {
		appendParam("environment_id", *environmentID)
	}

	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list rotation policies failed: %s", resp.Error.Error())
	}
	var result []*models.RotationPolicy
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

func (rs *RemoteStorage) UpdateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error {
	resp, err := rs.client.Put(ctx, fmt.Sprintf("/api/v1/rotation-policies/%d", p.ID), p)
	if err != nil {
		return fmt.Errorf("failed to update rotation policy: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update rotation policy failed: %s", resp.Error.Error())
	}
	var result models.RotationPolicy
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	*p = result
	return nil
}

func (rs *RemoteStorage) DeleteRotationPolicy(ctx context.Context, id uint) error {
	resp, err := rs.client.Delete(ctx, fmt.Sprintf("/api/v1/rotation-policies/%d", id))
	if err != nil {
		return fmt.Errorf("failed to delete rotation policy: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete rotation policy failed: %s", resp.Error.Error())
	}
	return nil
}
