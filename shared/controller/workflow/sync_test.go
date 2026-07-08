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
	"errors"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/shared/events"
)

const testOldHash = "old-hash"

// ---------------------------------------------------------------------------
// Sync-test helpers (reuses testResource, mockOps, newFakeK8sClient,
// newTestVaultClient, containsCall, findCondition from helpers_test.go)
// ---------------------------------------------------------------------------

// newTestVaultConnection creates a cluster-scoped VaultConnection for
// driftmode.Resolve to look up during sync.
func newTestVaultConnection() *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "test-connection", Generation: 1},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
		},
	}
}

// newTestPolicy creates a namespaced VaultPolicy for testing.
func newTestPolicy() *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
			ConflictPolicy: vaultv1alpha1.ConflictPolicyFail,
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
			},
		},
	}
}

// newTestResolver returns a VaultClientResolver that maps "test-connection"
// to a test Vault client and rejects everything else.
func newTestResolver(t *testing.T) VaultClientResolver {
	t.Helper()
	vc := newTestVaultClient(t)
	return func(_ context.Context, connRef, _ string) (VaultOpsClient, error) {
		if connRef == "test-connection" {
			return vc, nil
		}
		return nil, errors.New("unknown connection: " + connRef)
	}
}

// newSyncWorkflowForTest creates a SyncWorkflow wired with a fake K8s client,
// a test resolver, and an event bus. No recorder is attached (nil).
func newSyncWorkflowForTest(t *testing.T, k8s client.Client) *SyncWorkflow {
	t.Helper()
	bus := events.NewEventBus(logr.Discard())
	return NewSyncWorkflow(k8s, newTestResolver(t), bus, logr.Discard(), nil)
}

// assertCallOrder verifies that the recorded calls match the expected slice exactly.
func assertCallOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("call count mismatch: got %d %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSyncWorkflow_HappyPath(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{specHash: "abc123"}

	err := wf.Execute(context.Background(), res, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify call order
	expectedCalls := []string{
		"Validate",
		"CheckConflict",
		"PrepareContent",
		"WriteToVault",
		"ReadbackVerify",
		"ApplyBindings",
		"ApplyActiveStatus",
		"PublishSyncEvent",
	}
	assertCallOrder(t, ops.calls, expectedCalls)

	// Phase should be Active
	if res.GetPhase() != vaultv1alpha1.PhaseActive {
		t.Errorf("phase = %q, want %q", res.GetPhase(), vaultv1alpha1.PhaseActive)
	}

	// RetryCount should be 0
	if res.GetRetryCount() != 0 {
		t.Errorf("retryCount = %d, want 0", res.GetRetryCount())
	}

	// Message should be empty
	if res.Status.Message != "" {
		t.Errorf("message = %q, want empty", res.Status.Message)
	}

	// Verify conditions: Ready=True, Synced=True, DependencyReady=True, Drifted=False
	readyCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("Ready condition not found")
	}
	if readyCond.Status != metav1.ConditionTrue {
		t.Errorf("Ready status = %q, want %q", readyCond.Status, metav1.ConditionTrue)
	}

	syncedCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeSynced)
	if syncedCond == nil {
		t.Fatal("Synced condition not found")
	}
	if syncedCond.Status != metav1.ConditionTrue {
		t.Errorf("Synced status = %q, want %q", syncedCond.Status, metav1.ConditionTrue)
	}

	depCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeDependencyReady)
	if depCond == nil {
		t.Fatal("DependencyReady condition not found")
	}
	if depCond.Status != metav1.ConditionTrue {
		t.Errorf("DependencyReady status = %q, want %q", depCond.Status, metav1.ConditionTrue)
	}

	driftedCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeDrifted)
	if driftedCond == nil {
		t.Fatal("Drifted condition not found")
	}
	if driftedCond.Status != metav1.ConditionFalse {
		t.Errorf("Drifted status = %q, want %q", driftedCond.Status, metav1.ConditionFalse)
	}
}

// TestSyncWorkflow_HappyPath_RespectsPriorPoliciesResolvedFalse pins
// the fix for the bug where Ready=True/Succeeded was set
// unconditionally, even when the role handler had just set
// PoliciesResolved=False/PolicyNotInVault. Pre-fix, operators saw a
// "healthy" role whose bound policies didn't exist in Vault, so
// workloads using the role got no permissions while monitoring
// reported green. The workflow now downgrades Ready and
// DependencyReady to mirror the PoliciesResolved state.
func TestSyncWorkflow_HappyPath_RespectsPriorPoliciesResolvedFalse(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	// Simulate the role handler's verifyPoliciesExistInVault having set
	// PoliciesResolved=False/PolicyNotInVault on a prior step. The shared
	// workflow's finalize must honor this and refuse to stamp Ready=True.
	missingMsg := "policies not found in Vault: missing-policy"
	res.SetConditions([]vaultv1alpha1.Condition{
		{
			Type:    vaultv1alpha1.ConditionTypePoliciesResolved,
			Status:  metav1.ConditionFalse,
			Reason:  vaultv1alpha1.ReasonPolicyNotInVault,
			Message: missingMsg,
		},
	})
	ops := &mockOps{specHash: "abc123"}

	err := wf.Execute(context.Background(), res, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	readyCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("Ready condition not found")
	}
	if readyCond.Status != metav1.ConditionFalse {
		t.Errorf("Ready.Status = %q, want False (PoliciesResolved=False blocks)",
			readyCond.Status)
	}
	if readyCond.Reason != vaultv1alpha1.ReasonPolicyNotInVault {
		t.Errorf("Ready.Reason = %q, want %q",
			readyCond.Reason, vaultv1alpha1.ReasonPolicyNotInVault)
	}

	depCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeDependencyReady)
	if depCond == nil {
		t.Fatal("DependencyReady condition not found")
	}
	if depCond.Status != metav1.ConditionFalse {
		t.Errorf("DependencyReady.Status = %q, want False (mirrors PoliciesResolved)",
			depCond.Status)
	}

	// Synced should still be True — the spec was synced to Vault, only the
	// references couldn't be resolved.
	syncedCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeSynced)
	if syncedCond == nil || syncedCond.Status != metav1.ConditionTrue {
		t.Error("Synced should remain True even when PoliciesResolved is False")
	}
}

func TestSyncWorkflow_ValidateError(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:    "abc123",
		validateErr: errors.New("invalid policy: missing rules"),
	}

	err := wf.Execute(context.Background(), res, ops)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Only Validate should be called
	if !containsCall(ops.calls, "Validate") {
		t.Error("expected Validate to be called")
	}
	if containsCall(ops.calls, "CheckConflict") {
		t.Error("expected CheckConflict to NOT be called after Validate error")
	}
	if containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault to NOT be called after Validate error")
	}

	// Phase should be Error (set by syncerror.Handle)
	if res.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("phase = %q, want %q", res.GetPhase(), vaultv1alpha1.PhaseError)
	}
}

func TestSyncWorkflow_WriteToVaultError(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash: "abc123",
		writeErr: errors.New("vault unavailable"),
	}

	err := wf.Execute(context.Background(), res, ops)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Steps up through WriteToVault should be called
	if !containsCall(ops.calls, "Validate") {
		t.Error("expected Validate to be called")
	}
	if !containsCall(ops.calls, "CheckConflict") {
		t.Error("expected CheckConflict to be called")
	}
	if !containsCall(ops.calls, "PrepareContent") {
		t.Error("expected PrepareContent to be called")
	}
	if !containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault to be called")
	}

	// ReadbackVerify should NOT be called
	if containsCall(ops.calls, "ReadbackVerify") {
		t.Error("expected ReadbackVerify to NOT be called after WriteToVault error")
	}
}

func TestSyncWorkflow_ReadbackVerifyError(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:    "abc123",
		readbackErr: errors.New("readback mismatch"),
	}

	err := wf.Execute(context.Background(), res, ops)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Steps up through ReadbackVerify should be called
	if !containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault to be called")
	}
	if !containsCall(ops.calls, "ReadbackVerify") {
		t.Error("expected ReadbackVerify to be called")
	}

}

func TestSyncWorkflow_DriftDetect_SkipIfHashMatches(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeDetect
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = "same-hash"

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:      "same-hash",
		driftDetected: true,
		driftSummary:  "policy content differs",
	}

	err := wf.Execute(context.Background(), res, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// DetectDrift should be called (phase is Active and mode is detect)
	if !containsCall(ops.calls, "DetectDrift") {
		t.Error("expected DetectDrift to be called")
	}

	// WriteToVault should NOT be called (hash matches in detect mode -- early return)
	if containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault to NOT be called when hash matches in detect mode")
	}
}

func TestSyncWorkflow_DriftCorrect_BlockedWithoutAnnotation(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeCorrect
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = testOldHash

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:      "new-hash",
		driftDetected: true,
		driftSummary:  "policy content differs",
	}

	err := wf.Execute(context.Background(), res, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Phase should be Conflict
	if res.GetPhase() != vaultv1alpha1.PhaseConflict {
		t.Errorf("phase = %q, want %q", res.GetPhase(), vaultv1alpha1.PhaseConflict)
	}

	// WriteToVault should NOT be called
	if containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault to NOT be called without allow-destructive annotation")
	}

	// DriftDetected should be true
	if !res.GetDriftDetected() {
		t.Error("expected DriftDetected to be true")
	}
}

func TestSyncWorkflow_DriftCorrect_AllowedWithAnnotation(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeCorrect
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = testOldHash
	policy.Annotations = map[string]string{
		vaultv1alpha1.AnnotationAllowDestructive: vaultv1alpha1.AnnotationValueTrue,
	}

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:      "new-hash",
		driftDetected: true,
		driftSummary:  "policy content differs",
	}

	err := wf.Execute(context.Background(), res, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// WriteToVault should be called
	if !containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault to be called with allow-destructive annotation")
	}

	// Phase should be Active after completion
	if res.GetPhase() != vaultv1alpha1.PhaseActive {
		t.Errorf("phase = %q, want %q", res.GetPhase(), vaultv1alpha1.PhaseActive)
	}

	// Followup fix: the allow-destructive annotation must be auto-cleared
	// after the destructive write succeeds. Without this, a one-time
	// "I accept the risk" would become a standing permission for all
	// future drift corrections.
	var fresh vaultv1alpha1.VaultPolicy
	if err := k8s.Get(context.Background(),
		client.ObjectKey{Name: policy.Name, Namespace: policy.Namespace},
		&fresh); err != nil {
		t.Fatalf("failed to re-fetch policy: %v", err)
	}
	if _, present := fresh.Annotations[vaultv1alpha1.AnnotationAllowDestructive]; present {
		t.Error("allow-destructive annotation should be auto-cleared after a successful drift correction")
	}
}

// TestSyncWorkflow_DriftCorrect_DoesNotClearAnnotationWhenUnused pins
// the negative side: a successful sync that did NOT consume the
// allow-destructive path leaves the annotation alone (e.g. spec
// changes in detect mode while annotation is incidentally set).
func TestSyncWorkflow_DriftCorrect_DoesNotClearAnnotationWhenUnused(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	// detect mode → never enters the destructive path even with annotation set
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeDetect
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = testOldHash
	policy.Annotations = map[string]string{
		vaultv1alpha1.AnnotationAllowDestructive: vaultv1alpha1.AnnotationValueTrue,
	}

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)
	res := newTestResource(policy)
	ops := &mockOps{specHash: "new-hash"}

	if err := wf.Execute(context.Background(), res, ops); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var fresh vaultv1alpha1.VaultPolicy
	if err := k8s.Get(context.Background(),
		client.ObjectKey{Name: policy.Name, Namespace: policy.Namespace},
		&fresh); err != nil {
		t.Fatalf("failed to re-fetch policy: %v", err)
	}
	v, present := fresh.Annotations[vaultv1alpha1.AnnotationAllowDestructive]
	if !present || v != vaultv1alpha1.AnnotationValueTrue {
		t.Error("allow-destructive should remain when destructive correction was NOT triggered")
	}
}

func TestSyncWorkflow_SkipIfUnchanged(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeDetect
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = "same-hash"

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:      "same-hash",
		driftDetected: false,
	}

	err := wf.Execute(context.Background(), res, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// WriteToVault should NOT be called (unchanged, no drift)
	if containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault to NOT be called for unchanged resource with no drift")
	}

}

func TestSyncWorkflow_DriftIgnoreMode(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeIgnore
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = testOldHash

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash: "new-hash",
	}

	err := wf.Execute(context.Background(), res, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// DetectDrift should NOT be called (ignore mode)
	if containsCall(ops.calls, "DetectDrift") {
		t.Error("expected DetectDrift to NOT be called in ignore mode")
	}

	// DriftDetected should be false
	if res.GetDriftDetected() {
		t.Error("expected DriftDetected to be false in ignore mode")
	}

	// WriteToVault should be called (hash differs, so not skipped)
	if !containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault to be called when hash differs")
	}
}

// TestSyncWorkflow_DryRunCondition_True pins IMPROVEMENTS Missing
// Features §I: when the resource carries vault.platform.io/dry-run=true,
// the workflow's finalizeSuccessfulSync sets the DryRun condition to
// True with reason DryRunSkipped. The ops layer is responsible for
// actually skipping Vault writes (mockOps doesn't model that here).
func TestSyncWorkflow_DryRunCondition_True(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Annotations = map[string]string{
		vaultv1alpha1.AnnotationDryRun: vaultv1alpha1.AnnotationValueTrue,
	}
	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{specHash: "abc"}

	if err := wf.Execute(context.Background(), res, ops); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dryRunCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeDryRun)
	if dryRunCond == nil {
		t.Fatal("DryRun condition not found")
	}
	if dryRunCond.Status != metav1.ConditionTrue {
		t.Errorf("DryRun status = %q, want True", dryRunCond.Status)
	}
	if dryRunCond.Reason != vaultv1alpha1.ReasonDryRunSkipped {
		t.Errorf("DryRun reason = %q, want %q",
			dryRunCond.Reason, vaultv1alpha1.ReasonDryRunSkipped)
	}
	if !strings.Contains(dryRunCond.Message, "vault.platform.io/dry-run") {
		t.Errorf("DryRun message should mention the annotation; got %q", dryRunCond.Message)
	}
}

// TestSyncWorkflow_DryRunCondition_False covers the negative case: a
// resource WITHOUT the dry-run annotation gets DryRun=False.
func TestSyncWorkflow_DryRunCondition_False(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy() // no annotations
	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{specHash: "abc"}

	if err := wf.Execute(context.Background(), res, ops); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dryRunCond := findCondition(res.GetConditions(), vaultv1alpha1.ConditionTypeDryRun)
	if dryRunCond == nil {
		t.Fatal("DryRun condition should still be set (=False) for non-dry-run resources")
	}
	if dryRunCond.Status != metav1.ConditionFalse {
		t.Errorf("DryRun status = %q, want False", dryRunCond.Status)
	}
}

// ---------------------------------------------------------------------------
// Rename flow (ADR 0010): recorded name != bound name migrates the object.
// ---------------------------------------------------------------------------

const (
	renameOldName   = "old-name"
	renameBoundName = "vao._.default.test-policy"
	sameHash        = "same-hash"
	priorHash       = "abc123"
)

// TestSyncWorkflow_RenameWritesNewThenDeletesOld pins the rename ordering:
// the old-named object is deleted only AFTER the new-named object passed
// ReadbackVerify, so Vault never has zero copies.
func TestSyncWorkflow_RenameWritesNewThenDeletesOld(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = priorHash

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:     "new-hash",
		recordedName: renameOldName,
		boundName:    renameBoundName,
	}

	if err := wf.Execute(context.Background(), res, ops); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedCalls := []string{
		"Validate",
		"CheckConflict",
		"PrepareContent",
		"DetectDrift", // phase Active + default drift mode
		"WriteToVault",
		"ReadbackVerify",
		"DeleteFromVault", // stale old name — strictly after readback
		"ApplyBindings",
		"ApplyActiveStatus",
		"PublishSyncEvent",
	}
	assertCallOrder(t, ops.calls, expectedCalls)

	if len(ops.deletedNames) != 1 || ops.deletedNames[0] != renameOldName {
		t.Errorf("deletedNames = %v, want [old-name]", ops.deletedNames)
	}
}

// TestSyncWorkflow_RenameUnchangedHashStillWrites is load-bearing: a naming
// config change alone doesn't alter the spec hash, so without the
// staleVaultName guard the unchanged-resource early return would skip the
// write and the rename would never happen.
func TestSyncWorkflow_RenameUnchangedHashStillWrites(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = sameHash

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:     sameHash,      // unchanged spec
		recordedName: renameOldName, // …but the name moved
		boundName:    renameBoundName,
	}

	if err := wf.Execute(context.Background(), res, ops); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !containsCall(ops.calls, "WriteToVault") {
		t.Error("expected WriteToVault despite unchanged hash — rename pending")
	}
	if len(ops.deletedNames) != 1 || ops.deletedNames[0] != renameOldName {
		t.Errorf("deletedNames = %v, want [old-name]", ops.deletedNames)
	}
}

// TestSyncWorkflow_RenameDeleteFailureEnqueuesAndSucceeds pins that a failed
// stale-name delete never fails the sync (the new object is live) and lands
// the old name in the ADR 0005 cleanup queue for replay.
func TestSyncWorkflow_RenameDeleteFailureEnqueuesAndSucceeds(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = priorHash

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	queue := &fakeQueue{}
	wf := newSyncWorkflowForTest(t, k8s).WithCleanupQueue(queue)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:     "new-hash",
		recordedName: renameOldName,
		boundName:    renameBoundName,
		deleteErr:    errors.New("vault 500"),
	}

	if err := wf.Execute(context.Background(), res, ops); err != nil {
		t.Fatalf("sync must not fail on stale-delete failure, got: %v", err)
	}
	if res.GetPhase() != vaultv1alpha1.PhaseActive {
		t.Errorf("phase = %q, want Active", res.GetPhase())
	}

	items := queue.snapshot()
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item for the stale name, got %d", len(items))
	}
	if items[0].VaultName != renameOldName {
		t.Errorf("queue item VaultName = %q, want %q", items[0].VaultName, renameOldName)
	}
}

// TestSyncWorkflow_DryRunNeverDeletesStaleName pins the workflow-level
// dry-run guard: even with a pending rename, a dry-run must not delete the
// old-named (only real) Vault object.
func TestSyncWorkflow_DryRunNeverDeletesStaleName(t *testing.T) {
	t.Parallel()

	policy := newTestPolicy()
	policy.Annotations = map[string]string{vaultv1alpha1.AnnotationDryRun: vaultv1alpha1.AnnotationValueTrue}
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.LastAppliedHash = priorHash

	conn := newTestVaultConnection()
	k8s := newFakeK8sClient(t, policy, conn)
	wf := newSyncWorkflowForTest(t, k8s)

	res := newTestResource(policy)
	ops := &mockOps{
		specHash:     "new-hash",
		recordedName: renameOldName,
		boundName:    renameBoundName,
	}

	if err := wf.Execute(context.Background(), res, ops); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if containsCall(ops.calls, "DeleteFromVault") {
		t.Error("dry-run must never delete the stale (pre-rename) Vault object")
	}
}
