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

// Package markers holds the operator-wide toggle for managed-marker tracking.
//
// Managed markers are ownership records the operator writes to Vault KV v2
// custom_metadata (see pkg/vault/managed.go). They are opt-in: DISABLED by
// default, enabled via --managed-markers / MANAGED_MARKERS. When disabled the
// operator performs no marker reads/writes/lists, skips conflict/ownership
// detection, and does not run the discovery or orphan controllers — so it needs
// no grant on the marker KV path and no 403 is ever reachable.
package markers

import "sync/atomic"

// ponytail: enabled is an operator-wide switch set once at startup from
// --managed-markers and read-only thereafter, mirroring shared/naming.cluster.
// A package var avoids threading it through every ops constructor and handler
// (ops are value structs built inline at many call sites and in tests).
// Upgrade path: if per-connection toggles are ever needed, thread an explicit
// value through the adapters instead of this global.
var enabled atomic.Bool

// SetEnabled records whether managed-marker tracking is active. Call once at
// startup, before the manager starts.
func SetEnabled(on bool) { enabled.Store(on) }

// Enabled reports whether managed-marker tracking is active (false by default).
func Enabled() bool { return enabled.Load() }
