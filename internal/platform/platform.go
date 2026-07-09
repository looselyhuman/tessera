package platform

import "context"

// Adapter checks whether an agent has posted a nonce on a given platform.
type Adapter interface {
	VerifyNonce(ctx context.Context, agentName string, nonce string) (bool, error)
	Name() string
}
