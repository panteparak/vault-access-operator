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

package token

import "context"

// TokenProvider defines the strategy interface for acquiring service account tokens.
// Implementations include MountedTokenProvider (reads from file) and
// TokenRequestProvider (uses Kubernetes TokenRequest API).
//
// This follows the Strategy pattern - the LifecycleController works with any
// TokenProvider implementation without knowing the details of token acquisition.
//
// # Thread Safety
//
// Implementations must be thread-safe and support concurrent GetToken calls.
//
// # Implementations
//
//   - MountedTokenProvider: Reads token from mounted file (legacy approach)
//   - TokenRequestProvider: Uses Kubernetes TokenRequest API (recommended)
type TokenProvider interface {
	// GetToken acquires a service account token with the given options.
	// The returned TokenInfo contains the JWT and its expiration time.
	//
	// For TokenRequestProvider, Duration in options controls the token lifetime.
	// For MountedTokenProvider, Duration is ignored (uses mounted token's lifetime).
	GetToken(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error)
}
