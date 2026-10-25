package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error) {
	args := m.Called(ctx, inv)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (bool, error) {
	args := m.Called(ctx, inv)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) (bool, error) {
	args := m.Called(ctx, req)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	args := m.Called(ctx, a)
	return args.Error(0)
}

func (m *MockStorage) ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error) {
	args := m.Called(ctx, requestID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessRequestApproval), args.Error(1)
}

func (m *MockStorage) CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, c)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) GetOpenAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) GetLatestClosedAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error) {
	a := m.Called(ctx, projectID)
	v, _ := a.Get(0).(*models.AccessReviewCampaign)
	return v, a.Error(1)
}

func (m *MockStorage) UpdateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (bool, error) {
	args := m.Called(ctx, c)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	args := m.Called(ctx, items)
	return args.Error(0)
}

func (m *MockStorage) ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error) {
	args := m.Called(ctx, campaignID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessReviewItem), args.Error(1)
}

func (m *MockStorage) CountPendingAccessReviewItems(ctx context.Context, campaignID uint) (int, error) {
	args := m.Called(ctx, campaignID)
	return args.Int(0), args.Error(1)
}

func (m *MockStorage) GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewItem), args.Error(1)
}

func (m *MockStorage) UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) (bool, error) {
	args := m.Called(ctx, item)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error) {
	args := m.Called(ctx, p)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDPolicy), args.Error(1)
}

func (m *MockStorage) GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDPolicy), args.Error(1)
}

// ListSoDPolicies defaults to "no policies configured" when a test hasn't set up
// an expectation for it (mirrors GetProject/ListEnvironmentsByProject above) —
// #419 wired a ListSoDPolicies call into every role-grant choke point
// (requireNoSoDViolation and friends, sod.go), so any grant-path test that
// doesn't care about SoD would otherwise need to stub this out too.
func (m *MockStorage) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListSoDPolicies" {
			args := m.Called(ctx)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.SoDPolicy), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) DeleteSoDPolicy(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) CreateRejectionReasonTemplate(ctx context.Context, t *models.RejectionReasonTemplate) error {
	args := m.Called(ctx, t)
	return args.Error(0)
}

func (m *MockStorage) ListRejectionReasonTemplates(ctx context.Context) ([]models.RejectionReasonTemplate, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.RejectionReasonTemplate), args.Error(1)
}

func (m *MockStorage) DeleteRejectionReasonTemplate(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) ListAccessRequestsByIDs(ctx context.Context, ids []uint) ([]*models.AccessRequest, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessRequest), args.Error(1)
}
