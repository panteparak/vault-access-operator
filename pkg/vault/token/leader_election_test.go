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

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
)

// Both controllers run as manager Runnables and must be leader-gated so only
// one operator replica renews/rotates (IMPROVEMENTS §1).

func TestReviewerController_NeedsLeaderElection(t *testing.T) {
	c := NewTokenReviewerController(nil, nil, logr.Discard()).(*reviewerControllerImpl)
	if !c.NeedsLeaderElection() {
		t.Error("reviewer controller must require leader election")
	}
}

func TestLifecycleController_NeedsLeaderElection(t *testing.T) {
	c := NewLifecycleController(nil, nil, nil, logr.Discard()).(*lifecycleControllerImpl)
	if !c.NeedsLeaderElection() {
		t.Error("lifecycle controller must require leader election")
	}
}

func TestWithReviewerCheckInterval(t *testing.T) {
	c := NewTokenReviewerController(nil, nil, logr.Discard(),
		WithReviewerCheckInterval(2*time.Second)).(*reviewerControllerImpl)
	if c.checkInterval != 2*time.Second {
		t.Errorf("checkInterval = %v, want 2s", c.checkInterval)
	}

	// Non-positive values are ignored — the 60s default is retained.
	def := NewTokenReviewerController(nil, nil, logr.Discard(),
		WithReviewerCheckInterval(0)).(*reviewerControllerImpl)
	if def.checkInterval != 60*time.Second {
		t.Errorf("zero interval should retain the 60s default, got %v", def.checkInterval)
	}
}

func TestWithLifecycleCheckInterval(t *testing.T) {
	c := NewLifecycleController(nil, nil, nil, logr.Discard(),
		WithLifecycleCheckInterval(3*time.Second)).(*lifecycleControllerImpl)
	if c.checkInterval != 3*time.Second {
		t.Errorf("checkInterval = %v, want 3s", c.checkInterval)
	}
}
