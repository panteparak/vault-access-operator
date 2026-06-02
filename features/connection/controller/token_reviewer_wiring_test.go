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
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/pkg/vault/token"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// --- EventPublisher adapter ---

func TestEventBusPublisher_DeliversEventToBus(t *testing.T) {
	bus := events.NewEventBus(logr.Discard())
	got := 0
	events.Subscribe(bus, func(_ context.Context, _ events.TokenReviewerRefreshed) error {
		got++
		return nil
	})

	p := eventBusPublisher{bus: bus}
	err := p.Publish(context.Background(),
		events.NewTokenReviewerRefreshed("conn", time.Now(), time.Now()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("expected subscriber to receive exactly 1 event, got %d", got)
	}
}

func TestEventBusPublisher_NilBus_NoOp(t *testing.T) {
	p := eventBusPublisher{bus: nil}
	if err := p.Publish(context.Background(),
		events.NewTokenReviewerRefreshed("c", time.Now(), time.Now())); err != nil {
		t.Errorf("nil bus should be a no-op, got %v", err)
	}
}

func TestEventBusPublisher_NonEvent_Dropped(t *testing.T) {
	p := eventBusPublisher{bus: events.NewEventBus(logr.Discard())}
	if err := p.Publish(context.Background(), "not an event"); err != nil {
		t.Errorf("non-Event value should be dropped without error, got %v", err)
	}
}

// --- registerTokenReviewer wiring ---

// fakeReviewerController records calls and mimics the real controller's
// GetStatus contract: non-nil once Register has been called for a name.
type fakeReviewerController struct {
	registerCalls   []string
	setClientCalls  []string
	refreshCalls    []string
	unregisterCalls []string
	tracked         map[string]bool
}

func newFakeReviewerController() *fakeReviewerController {
	return &fakeReviewerController{tracked: map[string]bool{}}
}

func (f *fakeReviewerController) Start(context.Context) error { return nil }
func (f *fakeReviewerController) Register(name string, _ *token.ReviewerConfig) error {
	f.registerCalls = append(f.registerCalls, name)
	f.tracked[name] = true
	return nil
}
func (f *fakeReviewerController) SetVaultClient(name string, _ token.VaultAuthConfigUpdater) {
	f.setClientCalls = append(f.setClientCalls, name)
}
func (f *fakeReviewerController) Unregister(name string) {
	f.unregisterCalls = append(f.unregisterCalls, name)
	delete(f.tracked, name)
}
func (f *fakeReviewerController) Refresh(_ context.Context, name string) error {
	f.refreshCalls = append(f.refreshCalls, name)
	return nil
}
func (f *fakeReviewerController) GetStatus(name string) *token.TokenReviewerStatus {
	if f.tracked[name] {
		return &token.TokenReviewerStatus{ConnectionName: name}
	}
	return nil
}

func k8sAuthConn(name string, rotation *bool) *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{
					Role:                  "operator-role",
					TokenReviewerRotation: rotation,
				},
			},
		},
	}
}

// TestRegisterTokenReviewer_FirstRegistration pins the wiring that was missing
// (IMPROVEMENTS §1): on first sight of a connection the handler registers it,
// sets the Vault client, and primes the refresh schedule.
func TestRegisterTokenReviewer_FirstRegistration(t *testing.T) {
	fake := newFakeReviewerController()
	h := &Handler{reviewerCtrl: fake}
	conn := k8sAuthConn("conn-a", nil) // rotation enabled by default

	h.registerTokenReviewer(context.Background(), conn, &vault.Client{})

	if len(fake.registerCalls) != 1 || fake.registerCalls[0] != "conn-a" {
		t.Errorf("expected one Register(conn-a), got %v", fake.registerCalls)
	}
	if len(fake.setClientCalls) != 1 {
		t.Errorf("expected SetVaultClient once, got %v", fake.setClientCalls)
	}
	if len(fake.refreshCalls) != 1 {
		t.Errorf("expected initial Refresh once, got %v", fake.refreshCalls)
	}
}

// TestRegisterTokenReviewer_AlreadyTracked guards the state-reset trap: because
// the controller's Register REPLACES per-connection state (wiping NextRefresh),
// the handler must not re-Register or re-prime on subsequent reconciles — only
// refresh the client pointer.
func TestRegisterTokenReviewer_AlreadyTracked(t *testing.T) {
	fake := newFakeReviewerController()
	h := &Handler{reviewerCtrl: fake}
	conn := k8sAuthConn("conn-a", nil)

	h.registerTokenReviewer(context.Background(), conn, &vault.Client{}) // first
	h.registerTokenReviewer(context.Background(), conn, &vault.Client{}) // second reconcile

	if len(fake.registerCalls) != 1 {
		t.Errorf("expected Register exactly once across two reconciles, got %d", len(fake.registerCalls))
	}
	if len(fake.refreshCalls) != 1 {
		t.Errorf("expected initial Refresh exactly once, got %d", len(fake.refreshCalls))
	}
	if len(fake.setClientCalls) != 2 {
		t.Errorf("expected SetVaultClient on every reconcile (2), got %d", len(fake.setClientCalls))
	}
}

func TestRegisterTokenReviewer_RotationDisabled_Unregisters(t *testing.T) {
	fake := newFakeReviewerController()
	h := &Handler{reviewerCtrl: fake}
	disabled := false
	conn := k8sAuthConn("conn-a", &disabled)

	h.registerTokenReviewer(context.Background(), conn, &vault.Client{})

	if len(fake.registerCalls) != 0 {
		t.Errorf("rotation disabled must not Register, got %v", fake.registerCalls)
	}
	if len(fake.unregisterCalls) != 1 || fake.unregisterCalls[0] != "conn-a" {
		t.Errorf("rotation disabled must Unregister, got %v", fake.unregisterCalls)
	}
}

func TestRegisterTokenReviewer_NilController_NoPanic(t *testing.T) {
	h := &Handler{reviewerCtrl: nil}
	// Must not panic.
	h.registerTokenReviewer(context.Background(), k8sAuthConn("c", nil), &vault.Client{})
}

func TestRegisterTokenReviewer_NoKubernetesAuth_NoOp(t *testing.T) {
	fake := newFakeReviewerController()
	h := &Handler{reviewerCtrl: fake}
	conn := &vaultv1alpha1.VaultConnection{ObjectMeta: metav1.ObjectMeta{Name: "c"}}

	h.registerTokenReviewer(context.Background(), conn, &vault.Client{})

	if len(fake.registerCalls)+len(fake.setClientCalls)+len(fake.refreshCalls) != 0 {
		t.Error("non-Kubernetes auth connection should be a no-op for the reviewer")
	}
}
