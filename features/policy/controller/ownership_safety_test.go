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

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// AC1 (#18): an ownership-read error on delete is returned (so the caller
// queues a retry) and nothing is deleted.
func TestPolicyOps_DeleteFromVault_OwnershipReadErrorFailsClosed(t *testing.T) {
	m := newMockVaultClient()
	m.ownershipErr = errors.New("vault 500")
	ops := NewPolicyOps(domain.NewVaultPolicyAdapter(newTestVaultPolicy()), &Handler{})

	if err := ops.DeleteFromVault(context.Background(), m, "vao._.test-ns.app-read"); err == nil {
		t.Fatal("ownership read error must be returned, got nil")
	}
	if len(m.deletePolicyCalls) != 0 {
		t.Errorf("deleted on a read error: %v", m.deletePolicyCalls)
	}
}

// AC4 (#18): normalizeHCL strips the ownership header, so a same-content
// write by another owner used to pass readback. With checks on, readback
// fails unless the record read back is the one just written.
func TestPolicyOps_ReadbackVerify_OwnershipRecord(t *testing.T) {
	const name = "vao.cluster-a.test-ns.app-read"
	run := func(t *testing.T, markersOn bool, rewrite func(hcl string) string) error {
		t.Helper()
		if markersOn {
			enableMarkersForTest(t)
		}
		state := newPolicyMockState()
		server := newPolicyMockServer(policyMockConfig{state: state})
		t.Cleanup(server.Close)
		vc := newPolicyTestVaultClient(t, server.URL)
		vc.SetAuthMount("cluster-a")

		ops := NewPolicyOps(domain.NewVaultPolicyAdapter(newTestVaultPolicy()), &Handler{})
		ops.vaultName = name
		if _, err := ops.PrepareContent(context.Background(), vc); err != nil {
			t.Fatal(err)
		}
		state.policies[name] = rewrite(ops.hcl)
		return ops.ReadbackVerify(context.Background(), vc)
	}
	foreign := func(hcl string) string {
		return strings.Replace(hcl, "# auth-mount: cluster-a", "# auth-mount: cluster-b", 1)
	}

	t.Run("own record: ok", func(t *testing.T) {
		if err := run(t, true, func(h string) string { return h }); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
	t.Run("foreign record, identical rules: conflict", func(t *testing.T) {
		if err := run(t, true, foreign); !infraerrors.IsConflictError(err) {
			t.Errorf("want ConflictError, got %v", err)
		}
	})
	t.Run("checks off: rules only, as v0.12.0", func(t *testing.T) {
		if err := run(t, false, foreign); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
}

func newPolicyTestVaultClient(t *testing.T, url string) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: url})
	if err != nil {
		t.Fatal(err)
	}
	c.SetAuthenticated(true)
	c.SetToken("s.test")
	return c
}
