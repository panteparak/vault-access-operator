/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package events

import "time"

// Token event type constants.
const (
	TokenRenewedType           = "token.renewed"
	TokenRenewalFailedType     = "token.renewal_failed"
	TokenReviewerRefreshedType = "token.reviewer_refreshed"
	BootstrapCompletedType     = "bootstrap.completed"
)

// TokenRenewed is published when a Vault token is successfully renewed.
// Other features can subscribe to react to token refreshes if needed.
type TokenRenewed struct {
	BaseEvent
	// ConnectionName is the name of the VaultConnection
	ConnectionName string
	// NewExpiration is when the renewed token expires
	NewExpiration time.Time
	// RenewalCount is how many times this token has been renewed
	RenewalCount int
	// Method is how the token was refreshed: "renew" or "re-authenticate"
	Method string
}

// Type returns the event type identifier.
func (e TokenRenewed) Type() string {
	return TokenRenewedType
}

// NewTokenRenewed creates a TokenRenewed event.
func NewTokenRenewed(connectionName string, newExpiration time.Time, renewalCount int, method string) TokenRenewed {
	return TokenRenewed{
		BaseEvent:      NewBaseEvent(TokenRenewedType),
		ConnectionName: connectionName,
		NewExpiration:  newExpiration,
		RenewalCount:   renewalCount,
		Method:         method,
	}
}

// TokenRenewalFailed is published when token renewal fails.
// This allows for monitoring and alerting on token issues.
type TokenRenewalFailed struct {
	BaseEvent
	// ConnectionName is the name of the VaultConnection
	ConnectionName string
	// Error describes what went wrong
	Error string
	// RetryCount is how many retry attempts have been made
	RetryCount int
	// WillRetry indicates if another retry will be attempted
	WillRetry bool
}

// Type returns the event type identifier.
func (e TokenRenewalFailed) Type() string {
	return TokenRenewalFailedType
}

// NewTokenRenewalFailed creates a TokenRenewalFailed event.
func NewTokenRenewalFailed(connectionName, errMsg string, retryCount int, willRetry bool) TokenRenewalFailed {
	return TokenRenewalFailed{
		BaseEvent:      NewBaseEvent(TokenRenewalFailedType),
		ConnectionName: connectionName,
		Error:          errMsg,
		RetryCount:     retryCount,
		WillRetry:      willRetry,
	}
}

// TokenReviewerRefreshed is published when token_reviewer_jwt is updated in Vault.
// This is important for monitoring the health of Kubernetes auth.
type TokenReviewerRefreshed struct {
	BaseEvent
	// ConnectionName is the name of the VaultConnection
	ConnectionName string
	// NextRefresh is when the next refresh is scheduled
	NextRefresh time.Time
	// Expiration is when the current token_reviewer_jwt expires
	Expiration time.Time
}

// Type returns the event type identifier.
func (e TokenReviewerRefreshed) Type() string {
	return TokenReviewerRefreshedType
}

// NewTokenReviewerRefreshed creates a TokenReviewerRefreshed event.
func NewTokenReviewerRefreshed(connectionName string, nextRefresh, expiration time.Time) TokenReviewerRefreshed {
	return TokenReviewerRefreshed{
		BaseEvent:      NewBaseEvent(TokenReviewerRefreshedType),
		ConnectionName: connectionName,
		NextRefresh:    nextRefresh,
		Expiration:     expiration,
	}
}

// BootstrapCompleted is published when bootstrap finishes successfully.
// This signals that the connection has transitioned to Kubernetes auth.
type BootstrapCompleted struct {
	BaseEvent
	// ConnectionName is the name of the VaultConnection
	ConnectionName string
	// AuthPath is the Vault auth path (e.g., "auth/kubernetes")
	AuthPath string
	// BootstrapRevoked indicates if the bootstrap token was revoked
	BootstrapRevoked bool
	// TransitionedToK8s indicates if the connection now uses K8s auth
	TransitionedToK8s bool
}

// Type returns the event type identifier.
func (e BootstrapCompleted) Type() string {
	return BootstrapCompletedType
}

// NewBootstrapCompleted creates a BootstrapCompleted event.
func NewBootstrapCompleted(
	connectionName, authPath string, bootstrapRevoked, transitionedToK8s bool,
) BootstrapCompleted {
	return BootstrapCompleted{
		BaseEvent:         NewBaseEvent(BootstrapCompletedType),
		ConnectionName:    connectionName,
		AuthPath:          authPath,
		BootstrapRevoked:  bootstrapRevoked,
		TransitionedToK8s: transitionedToK8s,
	}
}
