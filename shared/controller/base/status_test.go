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

package base

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewStatusManager(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	sm := NewStatusManager[*corev1.ConfigMap](client, nil)

	if sm == nil {
		t.Fatal("expected StatusManager to be non-nil")
	}

	if sm.requeueOnSuccess != DefaultRequeueSuccess {
		t.Errorf("expected default requeueOnSuccess %v, got %v", DefaultRequeueSuccess, sm.requeueOnSuccess)
	}

	if sm.requeueOnError != DefaultRequeueError {
		t.Errorf("expected default requeueOnError %v, got %v", DefaultRequeueError, sm.requeueOnError)
	}
}

func TestStatusManager_WithRequeueOnSuccess(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	sm := NewStatusManager[*corev1.ConfigMap](client, nil).
		WithRequeueOnSuccess(10 * time.Minute)

	if sm.requeueOnSuccess != 10*time.Minute {
		t.Errorf("expected requeueOnSuccess 10m, got %v", sm.requeueOnSuccess)
	}
}

func TestStatusManager_WithRequeueOnError(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	sm := NewStatusManager[*corev1.ConfigMap](client, nil).
		WithRequeueOnError(1 * time.Minute)

	if sm.requeueOnError != 1*time.Minute {
		t.Errorf("expected requeueOnError 1m, got %v", sm.requeueOnError)
	}
}

func TestStatusManager_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	t.Run("without status updater", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()
		sm := NewStatusManager[*corev1.ConfigMap](client, nil)

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
		}

		result, err := sm.Success(context.Background(), cm)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		if result.RequeueAfter != DefaultRequeueSuccess {
			t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueSuccess, result.RequeueAfter)
		}
	})

	t.Run("with status updater", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()

		updaterCalled := false
		updater := func(_ context.Context, _ *corev1.ConfigMap, err error) error {
			updaterCalled = true
			if err != nil {
				t.Error("expected nil error in success updater call")
			}
			return nil
		}

		sm := NewStatusManager(client, updater)

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
		}

		result, err := sm.Success(context.Background(), cm)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		if !updaterCalled {
			t.Error("expected status updater to be called")
		}

		if result.RequeueAfter != DefaultRequeueSuccess {
			t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueSuccess, result.RequeueAfter)
		}
	})

	t.Run("with failing status updater", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()

		updater := func(_ context.Context, _ *corev1.ConfigMap, _ error) error {
			return errors.New("status update failed")
		}

		sm := NewStatusManager(client, updater)

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
		}

		// Success should not fail even if status updater fails
		result, err := sm.Success(context.Background(), cm)

		if err != nil {
			t.Errorf("expected no error (status update failure should be logged, not returned), got %v", err)
		}

		if result.RequeueAfter != DefaultRequeueSuccess {
			t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueSuccess, result.RequeueAfter)
		}
	})
}

func TestStatusManager_Error(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	t.Run("without status updater", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()
		sm := NewStatusManager[*corev1.ConfigMap](client, nil)

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
		}

		reconcileErr := errors.New("sync failed")
		result, err := sm.Error(context.Background(), cm, reconcileErr)

		if err != reconcileErr {
			t.Errorf("expected error %v, got %v", reconcileErr, err)
		}

		if result.RequeueAfter != DefaultRequeueError {
			t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueError, result.RequeueAfter)
		}
	})

	t.Run("with status updater", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()

		var receivedErr error
		updater := func(_ context.Context, _ *corev1.ConfigMap, err error) error {
			receivedErr = err
			return nil
		}

		sm := NewStatusManager(client, updater)

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
		}

		reconcileErr := errors.New("sync failed")
		result, err := sm.Error(context.Background(), cm, reconcileErr)

		if receivedErr != reconcileErr {
			t.Errorf("expected updater to receive error %v, got %v", reconcileErr, receivedErr)
		}

		if err != reconcileErr {
			t.Errorf("expected error %v, got %v", reconcileErr, err)
		}

		if result.RequeueAfter != DefaultRequeueError {
			t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueError, result.RequeueAfter)
		}
	})
}

func TestStatusManager_Requeue(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	sm := NewStatusManager[*corev1.ConfigMap](client, nil)

	result, err := sm.Requeue()

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter to be non-zero for immediate requeue")
	}
}

func TestStatusManager_RequeueAfter(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	sm := NewStatusManager[*corev1.ConfigMap](client, nil)

	result, err := sm.RequeueAfter(3 * time.Minute)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if result.RequeueAfter != 3*time.Minute {
		t.Errorf("expected RequeueAfter 3m, got %v", result.RequeueAfter)
	}
}

func TestStatusManager_Done(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	sm := NewStatusManager[*corev1.ConfigMap](client, nil)

	result, err := sm.Done()

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Errorf("expected RequeueAfter 0 (no requeue), got %v", result.RequeueAfter)
	}
}

func TestDefaultRequeueConstants(t *testing.T) {
	if DefaultRequeueSuccess != 5*time.Minute {
		t.Errorf("expected DefaultRequeueSuccess 5m, got %v", DefaultRequeueSuccess)
	}

	if DefaultRequeueError != 30*time.Second {
		t.Errorf("expected DefaultRequeueError 30s, got %v", DefaultRequeueError)
	}
}
