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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestNormalizeResource(t *testing.T) {
	tests := []struct {
		name           string
		input          map[string]interface{}
		expectedLabels map[string]string
	}{
		{
			name: "removes helm-specific labels",
			input: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ServiceAccount",
				"metadata": map[string]interface{}{
					"name": "test-sa",
					"labels": map[string]interface{}{
						"app.kubernetes.io/name":       "vault-access-operator",
						"helm.sh/chart":                "vault-access-operator-0.1.0",
						"app.kubernetes.io/instance":   "release-name",
						"app.kubernetes.io/version":    "0.1.0",
						"app.kubernetes.io/managed-by": "Helm",
					},
				},
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "vault-access-operator",
			},
		},
		{
			name: "removes kustomize managed-by label",
			input: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ServiceAccount",
				"metadata": map[string]interface{}{
					"name": "test-sa",
					"labels": map[string]interface{}{
						"app.kubernetes.io/name":       "vault-access-operator",
						"app.kubernetes.io/managed-by": "kustomize",
					},
				},
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "vault-access-operator",
			},
		},
		{
			name: "preserves app labels",
			input: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ServiceAccount",
				"metadata": map[string]interface{}{
					"name": "test-sa",
					"labels": map[string]interface{}{
						"app.kubernetes.io/name":      "vault-access-operator",
						"app.kubernetes.io/component": "controller",
					},
				},
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name":      "vault-access-operator",
				"app.kubernetes.io/component": "controller",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: tt.input}
			normalizeResource(obj)

			labels := obj.GetLabels()
			if len(labels) != len(tt.expectedLabels) {
				t.Errorf("expected %d labels, got %d: %v", len(tt.expectedLabels), len(labels), labels)
			}

			for k, v := range tt.expectedLabels {
				if labels[k] != v {
					t.Errorf("expected label %s=%s, got %s", k, v, labels[k])
				}
			}
		})
	}
}

func TestResourceKey(t *testing.T) {
	tests := []struct {
		name        string
		resource    Resource
		expectedKey string
	}{
		{
			name: "cluster-scoped resource",
			resource: Resource{
				kind: "ClusterRole",
				name: "manager-role",
			},
			expectedKey: "ClusterRole/manager-role",
		},
		{
			name: "namespace-scoped resource",
			resource: Resource{
				kind:      "Deployment",
				name:      "controller-manager",
				namespace: "system",
			},
			expectedKey: "Deployment/system/controller-manager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.resource.Key()
			if key != tt.expectedKey {
				t.Errorf("expected key %s, got %s", tt.expectedKey, key)
			}
		})
	}
}

func TestParseYAMLFile(t *testing.T) {
	// Create a temporary YAML file
	content := `---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-role
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	resources, err := parseYAMLFile(tmpFile)
	if err != nil {
		t.Fatalf("parseYAMLFile failed: %v", err)
	}

	if len(resources) != 2 {
		t.Errorf("expected 2 resources, got %d", len(resources))
	}

	// Check ServiceAccount
	saKey := "ServiceAccount/default/test-sa"
	if _, ok := resources[saKey]; !ok {
		t.Errorf("expected resource %s not found", saKey)
	}

	// Check ClusterRole
	crKey := "ClusterRole/test-role"
	if _, ok := resources[crKey]; !ok {
		t.Errorf("expected resource %s not found", crKey)
	}
}

func TestCompareResources(t *testing.T) {
	tests := []struct {
		name          string
		kustomize     map[string]interface{}
		helm          map[string]interface{}
		expectDiffs   bool
		criticalDiffs bool
	}{
		{
			name: "identical deployments",
			kustomize: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]interface{}{"name": "test"},
				"spec": map[string]interface{}{
					"replicas": int64(1),
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "manager",
									"image": "controller:latest",
									"args":  []interface{}{"--leader-elect"},
								},
							},
						},
					},
				},
			},
			helm: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]interface{}{"name": "test"},
				"spec": map[string]interface{}{
					"replicas": int64(1),
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "manager",
									"image": "controller:latest",
									"args":  []interface{}{"--leader-elect"},
								},
							},
						},
					},
				},
			},
			expectDiffs:   false,
			criticalDiffs: false,
		},
		{
			name: "different replicas",
			kustomize: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]interface{}{"name": "test"},
				"spec": map[string]interface{}{
					"replicas": int64(1),
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{},
						},
					},
				},
			},
			helm: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]interface{}{"name": "test"},
				"spec": map[string]interface{}{
					"replicas": int64(2),
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{},
						},
					},
				},
			},
			expectDiffs:   true,
			criticalDiffs: true,
		},
		{
			name: "only resource differences (non-critical)",
			kustomize: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]interface{}{"name": "test"},
				"spec": map[string]interface{}{
					"replicas": int64(1),
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "manager",
									"image": "controller:latest",
									"resources": map[string]interface{}{
										"limits": map[string]interface{}{
											"cpu": "500m",
										},
									},
								},
							},
						},
					},
				},
			},
			helm: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]interface{}{"name": "test"},
				"spec": map[string]interface{}{
					"replicas": int64(1),
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "manager",
									"image": "controller:latest",
									"resources": map[string]interface{}{
										"limits": map[string]interface{}{
											"cpu": "1000m",
										},
									},
								},
							},
						},
					},
				},
			},
			expectDiffs:   true,
			criticalDiffs: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kObj := &unstructured.Unstructured{Object: tt.kustomize}
			hObj := &unstructured.Unstructured{Object: tt.helm}

			diffs := compareResources(kObj, hObj)

			if tt.expectDiffs && len(diffs) == 0 {
				t.Error("expected differences but found none")
			}
			if !tt.expectDiffs && len(diffs) > 0 {
				t.Errorf("expected no differences but found: %v", diffs)
			}

			if tt.criticalDiffs {
				hasCritical := false
				for _, diff := range diffs {
					if isCriticalDifference(diff) {
						hasCritical = true
						break
					}
				}
				if !hasCritical {
					t.Error("expected critical differences but found none")
				}
			}
		})
	}
}

func TestCompareRBACRules(t *testing.T) {
	kustomize := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "ClusterRole",
			"metadata":   map[string]interface{}{"name": "test-role"},
			"rules": []interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"resources": []interface{}{"pods"},
					"verbs":     []interface{}{"get", "list"},
				},
			},
		},
	}

	helm := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "ClusterRole",
			"metadata":   map[string]interface{}{"name": "test-role"},
			"rules": []interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"resources": []interface{}{"pods"},
					"verbs":     []interface{}{"get", "list"},
				},
			},
		},
	}

	diffs := compareRBACRules(kustomize, helm)
	if len(diffs) > 0 {
		t.Errorf("expected no differences for identical rules, got: %v", diffs)
	}

	// Modify helm rules
	helm.Object["rules"] = []interface{}{
		map[string]interface{}{
			"apiGroups": []interface{}{""},
			"resources": []interface{}{"pods", "secrets"},
			"verbs":     []interface{}{"get", "list"},
		},
	}

	diffs = compareRBACRules(kustomize, helm)
	if len(diffs) == 0 {
		t.Error("expected differences for different rules")
	}
}

func TestIsCriticalDifference(t *testing.T) {
	tests := []struct {
		name     string
		diff     Difference
		critical bool
	}{
		{
			name:     "resource difference is not critical",
			diff:     Difference{Path: "containers[0].resources (non-critical)"},
			critical: false,
		},
		{
			name:     "replica difference is critical",
			diff:     Difference{Path: "spec.replicas"},
			critical: true,
		},
		{
			name:     "RBAC rules difference is critical",
			diff:     Difference{Path: "rules"},
			critical: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCriticalDifference(tt.diff)
			if result != tt.critical {
				t.Errorf("expected isCriticalDifference=%v, got %v", tt.critical, result)
			}
		})
	}
}
