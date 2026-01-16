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

// Package bootstrap provides one-time setup orchestration for Vault Kubernetes auth.
//
// # Overview
//
// When deploying the operator for the first time, the Vault Kubernetes auth method
// may not be configured. This package handles the bootstrap process:
//
//  1. Authenticate with a bootstrap token (one-time use)
//  2. Enable auth/kubernetes if not present
//  3. Configure kubernetes_host and kubernetes_ca_cert
//  4. Set initial token_reviewer_jwt
//  5. Create the operator's Vault role
//  6. Test Kubernetes auth works
//  7. Revoke the bootstrap token
//
// After bootstrap completes, the operator uses Kubernetes auth exclusively.
//
// # Security
//
// The bootstrap token should have a short TTL and be auto-revoked after setup.
// See the Setup Guide in the operator documentation for details.
//
// # Usage
//
//	manager := NewBootstrapManager(k8sClientset, log)
//	result, err := manager.Bootstrap(ctx, vaultClient, config)
//	if err != nil {
//	    return err
//	}
//	// Bootstrap complete, switch to K8s auth
//
// # Bootstrap Flow
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                       Bootstrap Process                          │
//	└─────────────────────────────────────────────────────────────────┘
//	                              │
//	                              ▼
//	┌─────────────────────────────────────────────────────────────────┐
//	│ 1. Authenticate with Bootstrap Token                             │
//	│    - Read token from Kubernetes secret                           │
//	│    - Authenticate to Vault                                       │
//	└─────────────────────────────────────────────────────────────────┘
//	                              │
//	                              ▼
//	┌─────────────────────────────────────────────────────────────────┐
//	│ 2. Enable Kubernetes Auth Method                                 │
//	│    - Check if auth/kubernetes exists                             │
//	│    - Enable if not present                                       │
//	└─────────────────────────────────────────────────────────────────┘
//	                              │
//	                              ▼
//	┌─────────────────────────────────────────────────────────────────┐
//	│ 3. Configure Kubernetes Auth                                     │
//	│    - Set kubernetes_host (auto-discovered or manual)             │
//	│    - Set kubernetes_ca_cert                                      │
//	│    - Set initial token_reviewer_jwt                              │
//	└─────────────────────────────────────────────────────────────────┘
//	                              │
//	                              ▼
//	┌─────────────────────────────────────────────────────────────────┐
//	│ 4. Create Operator Role                                          │
//	│    - Create Vault role for the operator                          │
//	│    - Bind to operator's service account                          │
//	└─────────────────────────────────────────────────────────────────┘
//	                              │
//	                              ▼
//	┌─────────────────────────────────────────────────────────────────┐
//	│ 5. Test & Cleanup                                                │
//	│    - Test K8s auth works                                         │
//	│    - Revoke bootstrap token (if auto-revoke enabled)             │
//	└─────────────────────────────────────────────────────────────────┘
package bootstrap
