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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

type fakeMounts struct {
	mounts []string
	err    error
	calls  int
}

func (f *fakeMounts) AuthMountNames(context.Context) ([]string, error) {
	f.calls++
	return f.mounts, f.err
}

func identityConn(name string) *vaultv1alpha1.VaultConnection {
	c := &vaultv1alpha1.VaultConnection{ObjectMeta: metav1.ObjectMeta{Name: "c"}}
	if name != "" {
		c.Spec.Identity = &vaultv1alpha1.ConnectionIdentity{Name: name}
	}
	return c
}

// TestResolveIdentity pins #18 AC5 (controller re-checks the CRD pattern),
// AC6 (precedence, reported in status.identity) and AC8 (an identity equal to
// an auth mount's sanitized name, or "_", is refused; sys/auth unreadable =
// refused, fail closed).
func TestResolveIdentity(t *testing.T) {
	mounts := []string{"kubernetes", "teams/pe", "K8S-Prod", "token"}
	for _, tc := range []struct {
		name, spec, cluster, login string
		listErr                    error
		wantStatus                 vaultv1alpha1.IdentityStatus
		wantReason                 string // "" = no error; "-" = plain error (reason Failed)
		wantListCalls              int
	}{
		{name: "spec identity", spec: "my-project", login: "kubernetes",
			wantStatus: vaultv1alpha1.IdentityStatus{Name: "my-project", Source: naming.SourceSpec}, wantListCalls: 1},
		{name: "no spec: cluster name", cluster: "pe", login: "kubernetes",
			wantStatus: vaultv1alpha1.IdentityStatus{Name: "pe", Source: naming.SourceClusterName}},
		{name: "no spec: login mount", login: "teams/pe",
			wantStatus: vaultv1alpha1.IdentityStatus{Name: "teams-pe", Source: naming.SourceAuthMount}},
		{name: "no spec, static token", wantStatus: vaultv1alpha1.IdentityStatus{Name: "_", Source: naming.SourceNone}},
		{name: "no spec: sys/auth not read even when unreadable", listErr: errors.New("403"),
			wantStatus: vaultv1alpha1.IdentityStatus{Name: "_", Source: naming.SourceNone}},
		{name: "equals a mount", spec: "kubernetes",
			wantReason: vaultv1alpha1.ReasonIdentityCollidesWithAuthMount, wantListCalls: 1},
		{name: "equals a nested mount's sanitized name", spec: "teams-pe",
			wantReason: vaultv1alpha1.ReasonIdentityCollidesWithAuthMount, wantListCalls: 1},
		{name: "equals a mount case-insensitively", spec: "k8s-prod",
			wantReason: vaultv1alpha1.ReasonIdentityCollidesWithAuthMount, wantListCalls: 1},
		{name: "equals the always-on token mount", spec: "token",
			wantReason: vaultv1alpha1.ReasonIdentityCollidesWithAuthMount, wantListCalls: 1},
		{name: "placeholder", spec: "_", wantReason: vaultv1alpha1.ReasonIdentityCollidesWithAuthMount},
		{name: "uppercase (CRD pattern)", spec: "Proj", wantReason: vaultv1alpha1.ReasonValidationFailed},
		{name: "dotted (CRD pattern)", spec: "a.b", wantReason: vaultv1alpha1.ReasonValidationFailed},
		{name: "too long (CRD maxLength)", spec: strings.Repeat("a", 41), wantReason: vaultv1alpha1.ReasonValidationFailed},
		{name: "sys/auth unreadable: fail closed", spec: "my-project", listErr: errors.New("403"),
			wantReason: "-", wantListCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			naming.SetCluster(tc.cluster)
			t.Cleanup(func() { naming.SetCluster("") })
			lister := &fakeMounts{mounts: mounts, err: tc.listErr}
			status, err := resolveIdentity(context.Background(), identityConn(tc.spec), lister, tc.login)
			switch {
			case tc.wantReason == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantReason == "-":
				if err == nil || classifyConnectionError(err) != vaultv1alpha1.ReasonFailed {
					t.Fatalf("want a plain error (reason Failed), got %v", err)
				}
			case tc.wantReason != "":
				if err == nil {
					t.Fatalf("want refusal %s, got status %+v", tc.wantReason, status)
				}
				if got := classifyConnectionError(err); got != tc.wantReason {
					t.Fatalf("reason = %s, want %s (%v)", got, tc.wantReason, err)
				}
			default:
				if status != tc.wantStatus {
					t.Errorf("status = %+v, want %+v", status, tc.wantStatus)
				}
			}
			if lister.calls != tc.wantListCalls {
				t.Errorf("sys/auth reads = %d, want %d (only connections that set an identity read it)",
					lister.calls, tc.wantListCalls)
			}
		})
	}
}
