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

// Package conditions provides a shared helper for setting Kubernetes-style
// status conditions on Vault CRD resources.
package conditions

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// Set updates an existing condition of the given type, or appends a new one.
// When the status has not changed, only the Reason, Message, and ObservedGeneration
// are updated (preserving LastTransitionTime). Returns the updated slice.
func Set(
	conditions []vaultv1alpha1.Condition,
	generation int64,
	condType string,
	status metav1.ConditionStatus,
	reason, message string,
) []vaultv1alpha1.Condition {
	now := metav1.Now()
	condition := vaultv1alpha1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	}

	for i, c := range conditions {
		if c.Type == condType {
			if c.Status != status {
				conditions[i] = condition
			} else {
				conditions[i].Reason = reason
				conditions[i].Message = message
				conditions[i].ObservedGeneration = generation
			}
			return conditions
		}
	}

	return append(conditions, condition)
}
