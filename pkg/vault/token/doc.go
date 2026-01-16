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

// Package token provides token lifecycle management for Vault authentication.
//
// # Overview
//
// This package handles service account token acquisition, Vault token renewal,
// and token_reviewer_jwt rotation. It follows the Strategy pattern for token
// acquisition and provides a controller-based lifecycle management system.
//
// # Key Interfaces
//
//   - TokenProvider: Strategy for acquiring service account tokens
//   - LifecycleController: Manages Vault token renewal with proactive refresh
//   - TokenReviewerController: Manages token_reviewer_jwt rotation in Vault
//
// # Usage
//
// The LifecycleController runs as a background goroutine and handles token
// renewal automatically. It can be started via manager.Runnable interface.
//
//	provider := NewTokenRequestProvider(k8sClientset, log)
//	controller := NewLifecycleController(provider, config, log)
//	mgr.Add(controller) // Runs as manager runnable
//
// # Token Flow
//
//	┌─────────────────┐    GetToken     ┌────────────────┐
//	│  TokenProvider  │ ──────────────> │   TokenInfo    │
//	│  (Strategy)     │                 │   (JWT + TTL)  │
//	└─────────────────┘                 └────────────────┘
//	        │
//	        ▼ Used by
//	┌─────────────────────────────────────────────────────┐
//	│            LifecycleController                       │
//	│  • Tracks token expiration per connection            │
//	│  • Proactively renews at configurable threshold      │
//	│  • Falls back to re-authentication on failure        │
//	│  • Publishes TokenRenewed events                     │
//	└─────────────────────────────────────────────────────┘
//
// # Design Patterns
//
// This package uses several design patterns from the codebase:
//
//   - Strategy Pattern: TokenProvider interface with multiple implementations
//   - Controller Pattern: LifecycleController manages background renewal
//   - Dependency Injection: All dependencies passed via constructors
package token
