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

package authprovider

import (
	"context"
	"errors"
	"testing"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

type stubProvider struct {
	name    string
	applies bool
	err     error
	calls   *[]string
}

func (s *stubProvider) Applies(_ vaultv1alpha1.AuthConfig) bool { return s.applies }

func (s *stubProvider) Authenticate(
	_ context.Context, _ VaultAuthenticator, _ *vaultv1alpha1.VaultConnection,
) error {
	*s.calls = append(*s.calls, s.name)
	return s.err
}

func TestRegistry_DispatchesToFirstApplicable(t *testing.T) {
	var calls []string
	reg := NewRegistry(
		&stubProvider{name: "first", applies: false, calls: &calls},
		&stubProvider{name: "second", applies: true, calls: &calls},
		&stubProvider{name: "third", applies: true, calls: &calls},
	)

	conn := &vaultv1alpha1.VaultConnection{}
	if err := reg.Authenticate(context.Background(), &fakeAuthenticator{}, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 || calls[0] != "second" {
		t.Errorf("expected only 'second' provider to be called, got %v", calls)
	}
}

func TestRegistry_ReturnsProviderError(t *testing.T) {
	sentinel := errors.New("boom")
	var calls []string
	reg := NewRegistry(&stubProvider{name: "only", applies: true, err: sentinel, calls: &calls})

	err := reg.Authenticate(context.Background(), &fakeAuthenticator{}, &vaultv1alpha1.VaultConnection{})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestRegistry_NoMatchReturnsErrNoProviderMatched(t *testing.T) {
	var calls []string
	reg := NewRegistry(&stubProvider{name: "skipped", applies: false, calls: &calls})

	err := reg.Authenticate(context.Background(), &fakeAuthenticator{}, &vaultv1alpha1.VaultConnection{})
	if !errors.Is(err, ErrNoProviderMatched) {
		t.Errorf("expected ErrNoProviderMatched, got %v", err)
	}
	if len(calls) != 0 {
		t.Errorf("expected no providers called, got %v", calls)
	}
}

func TestRegistry_EmptyProvidersReturnsErr(t *testing.T) {
	reg := NewRegistry()
	err := reg.Authenticate(context.Background(), &fakeAuthenticator{}, &vaultv1alpha1.VaultConnection{})
	if !errors.Is(err, ErrNoProviderMatched) {
		t.Errorf("expected ErrNoProviderMatched, got %v", err)
	}
}
