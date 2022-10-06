package core

import (
	"context"
	"errors"

	"github.com/mysocketio/mysocketctl-go/internal/api"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"go.uber.org/zap"
)

var ErrPolicyNotFound = errors.New("we couldn't find the policy")
var ErrEmptyPolicyList = errors.New("policy list is empty")

type PolicyManager struct {
	mysocketAPI api.API
	logger      *zap.Logger
}

func NewPolicyManager(logger *zap.Logger, api api.API) *PolicyManager {
	return &PolicyManager{api, logger}
}

func (p *PolicyManager) ApplyPolicies(ctx context.Context, socket models.Socket, apiPolicies, localPolicies []string) ([]string, error) {
	if len(localPolicies) == 0 && len(apiPolicies) == 0 {
		return nil, ErrEmptyPolicyList
	}

	// calculate the policies to attach
	var policiesToAttach []string
	for _, policyName := range localPolicies {
		policy, err := p.mysocketAPI.GetPolicyByName(ctx, policyName)
		if err != nil {
			switch err {
			case api.ErrNotFound:
				p.logger.Warn(ErrPolicyNotFound.Error(), zap.String("policy_name", policyName), zap.String("socket_name", socket.Name))
				continue
			default:
				continue
			}
		}

		policiesToAttach = append(policiesToAttach, policy.ID)
	}

	if len(policiesToAttach) > 0 {
		if _, err := p.mysocketAPI.AttachPolicies(ctx, socket.SocketID, policiesToAttach); err != nil {
			return nil, err
		}
	}

	// calculate the policies to detach
	if len(apiPolicies) > 0 {
		currentSocketPolicies, err := p.mysocketAPI.GetPoliciesBySocketID(socket.SocketID)
		if err != nil {
			return nil, err
		}

		var policiesToDetach []string
		for _, policy := range currentSocketPolicies {
			if !StringInSlice(policy.Name, localPolicies) {
				policiesToDetach = append(policiesToDetach, policy.ID)
			}
		}

		if len(policiesToDetach) > 0 {
			if _, err := p.mysocketAPI.DetachPolicies(ctx, socket.SocketID, policiesToDetach); err != nil {
				return nil, err
			}
		}
	}

	return policiesToAttach, nil
}
