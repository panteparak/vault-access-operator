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

package workflow

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// captureLogger returns a logger that records every emitted line and a
// pointer to the captured output.
func captureLogger() (logr.Logger, *string) {
	var captured string
	l := funcr.New(func(_, args string) { captured = args }, funcr.Options{})
	return l, &captured
}

func enrichTestResource() *testResource {
	return newTestResource(&vaultv1alpha1.VaultPolicy{
		Spec: vaultv1alpha1.VaultPolicySpec{ConnectionRef: "vault-main"},
	})
}

func TestEnrichLogContext_AddsConnectionAndAuthPath(t *testing.T) {
	base, captured := captureLogger()

	ctx := enrichLogContext(
		logr.NewContext(context.Background(), base),
		enrichTestResource(),
		&mockOps{authPath: "auth/kubernetes"},
	)
	logr.FromContextOrDiscard(ctx).Info("probe")

	for _, want := range []string{`"vaultConnection"="vault-main"`, `"authPath"="auth/kubernetes"`} {
		if !strings.Contains(*captured, want) {
			t.Errorf("log line missing %s, got: %s", want, *captured)
		}
	}
}

func TestEnrichLogContext_OmitsEmptyAuthPath(t *testing.T) {
	base, captured := captureLogger()

	// Policies return "" from AuthPath() — the field must not appear at all.
	ctx := enrichLogContext(
		logr.NewContext(context.Background(), base),
		enrichTestResource(),
		&mockOps{},
	)
	logr.FromContextOrDiscard(ctx).Info("probe")

	if strings.Contains(*captured, "authPath") {
		t.Errorf("authPath should be omitted when ops has none, got: %s", *captured)
	}
	if !strings.Contains(*captured, `"vaultConnection"="vault-main"`) {
		t.Errorf("log line missing vaultConnection, got: %s", *captured)
	}
}
