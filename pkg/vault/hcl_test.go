package vault

import (
	"strings"
	"testing"
)

func TestSubstituteVariables(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		namespace string
		resName   string
		want      string
	}{
		{
			name:      "no variables",
			path:      "secret/data/app",
			namespace: "default",
			resName:   "my-app",
			want:      "secret/data/app",
		},
		{
			name:      "namespace variable only",
			path:      "secret/data/{{namespace}}/config",
			namespace: "production",
			resName:   "my-app",
			want:      "secret/data/production/config",
		},
		{
			name:      "name variable only",
			path:      "secret/data/apps/{{name}}",
			namespace: "default",
			resName:   "my-service",
			want:      "secret/data/apps/my-service",
		},
		{
			name:      "both variables",
			path:      "secret/data/{{namespace}}/{{name}}/*",
			namespace: "staging",
			resName:   "api-server",
			want:      "secret/data/staging/api-server/*",
		},
		{
			name:      "multiple occurrences",
			path:      "{{namespace}}/{{namespace}}/{{name}}/{{name}}",
			namespace: "ns",
			resName:   "app",
			want:      "ns/ns/app/app",
		},
		{
			name:      "empty namespace",
			path:      "secret/data/{{namespace}}/config",
			namespace: "",
			resName:   "my-app",
			want:      "secret/data//config",
		},
		{
			name:      "empty name",
			path:      "secret/data/apps/{{name}}",
			namespace: "default",
			resName:   "",
			want:      "secret/data/apps/",
		},
		{
			name:      "special characters in values",
			path:      "secret/data/{{namespace}}/{{name}}",
			namespace: "my-namespace",
			resName:   "my-app-v2.1",
			want:      "secret/data/my-namespace/my-app-v2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SubstituteVariables(tt.path, tt.namespace, tt.resName)
			if got != tt.want {
				t.Errorf("SubstituteVariables() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []string
		wantErr      bool
		errContains  string
	}{
		{
			name:         "valid single capability - read",
			capabilities: []string{"read"},
			wantErr:      false,
		},
		{
			name:         "valid single capability - create",
			capabilities: []string{"create"},
			wantErr:      false,
		},
		{
			name:         "valid multiple capabilities",
			capabilities: []string{"create", "read", "update", "delete", "list"},
			wantErr:      false,
		},
		{
			name:         "valid sudo capability",
			capabilities: []string{"read", "sudo"},
			wantErr:      false,
		},
		{
			name:         "valid deny alone",
			capabilities: []string{"deny"},
			wantErr:      false,
		},
		{
			name:         "invalid capability",
			capabilities: []string{"invalid"},
			wantErr:      true,
			errContains:  "invalid capability",
		},
		{
			name:         "deny combined with other capability",
			capabilities: []string{"deny", "read"},
			wantErr:      true,
			errContains:  "deny",
		},
		{
			name:         "deny combined with multiple capabilities",
			capabilities: []string{"create", "deny", "update"},
			wantErr:      true,
			errContains:  "deny",
		},
		{
			name:         "empty capabilities",
			capabilities: []string{},
			wantErr:      false,
		},
		{
			name:         "mixed valid and invalid",
			capabilities: []string{"read", "write", "delete"},
			wantErr:      true,
			errContains:  "invalid capability: write",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCapabilities(tt.capabilities)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCapabilities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateCapabilities() error = %q, should contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid simple path",
			path:    "secret/data/app",
			wantErr: false,
		},
		{
			name:    "valid path with wildcard",
			path:    "secret/data/*",
			wantErr: false,
		},
		{
			name:    "valid path with glob pattern",
			path:    "secret/data/+/config",
			wantErr: false,
		},
		{
			name:    "valid path with variables",
			path:    "secret/data/{{namespace}}/{{name}}/*",
			wantErr: false,
		},
		{
			name:        "empty path",
			path:        "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "path with double dots",
			path:        "secret/../data/app",
			wantErr:     true,
			errContains: "..",
		},
		{
			name:        "path ending with double dots",
			path:        "secret/data/..",
			wantErr:     true,
			errContains: "..",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidatePath() error = %q, should contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestContainsNamespaceVariable(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "contains namespace variable",
			path: "secret/data/{{namespace}}/config",
			want: true,
		},
		{
			name: "no namespace variable",
			path: "secret/data/app/config",
			want: false,
		},
		{
			name: "only name variable",
			path: "secret/data/{{name}}",
			want: false,
		},
		{
			name: "both variables",
			path: "secret/{{namespace}}/{{name}}",
			want: true,
		},
		{
			name: "partial variable syntax",
			path: "secret/{{namespace/config",
			want: false,
		},
		{
			name: "empty path",
			path: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContainsNamespaceVariable(tt.path)
			if got != tt.want {
				t.Errorf("ContainsNamespaceVariable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasWildcardBeforeNamespace(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "wildcard before namespace",
			path: "secret/*/{{namespace}}/config",
			want: true,
		},
		{
			name: "wildcard after namespace",
			path: "secret/{{namespace}}/*/config",
			want: false,
		},
		{
			name: "no wildcard",
			path: "secret/data/{{namespace}}/config",
			want: false,
		},
		{
			name: "no namespace variable",
			path: "secret/*/config",
			want: false,
		},
		{
			name: "wildcard at start",
			path: "*/{{namespace}}/config",
			want: true,
		},
		{
			name: "both wildcard positions",
			path: "secret/*/{{namespace}}/*/config",
			want: true,
		},
		{
			name: "empty path",
			path: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasWildcardBeforeNamespace(tt.path)
			if got != tt.want {
				t.Errorf("HasWildcardBeforeNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGeneratePolicyHCL(t *testing.T) {
	tests := []struct {
		name      string
		rules     []PolicyRule
		namespace string
		resName   string
		want      []string // strings that must be present in output
		notWant   []string // strings that must not be present in output
	}{
		{
			name: "simple policy with one rule",
			rules: []PolicyRule{
				{
					Path:         "secret/data/app",
					Capabilities: []string{"read"},
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				"# Vault policy managed by vault-access-operator",
				"# Kubernetes resource: default/my-app",
				`path "secret/data/app"`,
				`capabilities = ["read"]`,
			},
		},
		{
			name: "policy with variable substitution",
			rules: []PolicyRule{
				{
					Path:         "secret/data/{{namespace}}/{{name}}/*",
					Capabilities: []string{"read", "list"},
				},
			},
			namespace: "production",
			resName:   "api-server",
			want: []string{
				`path "secret/data/production/api-server/*"`,
				`capabilities = ["read", "list"]`,
			},
		},
		{
			name: "policy with description",
			rules: []PolicyRule{
				{
					Path:         "secret/data/config",
					Capabilities: []string{"read"},
					Description:  "Read access to configuration secrets",
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				"# Read access to configuration secrets",
				`path "secret/data/config"`,
			},
		},
		{
			name: "policy with multiple rules",
			rules: []PolicyRule{
				{
					Path:         "secret/data/app/*",
					Capabilities: []string{"read", "list"},
					Description:  "Read app secrets",
				},
				{
					Path:         "secret/metadata/app/*",
					Capabilities: []string{"list"},
					Description:  "List secret metadata",
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				`path "secret/data/app/*"`,
				`capabilities = ["read", "list"]`,
				`path "secret/metadata/app/*"`,
				`capabilities = ["list"]`,
				"# Read app secrets",
				"# List secret metadata",
			},
		},
		{
			name: "policy with allowed parameters",
			rules: []PolicyRule{
				{
					Path:         "secret/data/config",
					Capabilities: []string{"create", "update"},
					Parameters: &PolicyParameters{
						Allowed: []string{"value1", "value2"},
					},
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				`capabilities = ["create", "update"]`,
				"allowed_parameters",
				`"value1"`,
				`"value2"`,
			},
		},
		{
			name: "policy with denied parameters",
			rules: []PolicyRule{
				{
					Path:         "secret/data/config",
					Capabilities: []string{"update"},
					Parameters: &PolicyParameters{
						Denied: []string{"secret_key", "password"},
					},
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				"denied_parameters",
				`"secret_key"`,
				`"password"`,
			},
		},
		{
			name: "policy with required parameters",
			rules: []PolicyRule{
				{
					Path:         "secret/data/config",
					Capabilities: []string{"create"},
					Parameters: &PolicyParameters{
						Required: []string{"app_name", "version"},
					},
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				"required_parameters",
				`"app_name"`,
				`"version"`,
			},
		},
		{
			name: "policy with all parameter types",
			rules: []PolicyRule{
				{
					Path:         "secret/data/config",
					Capabilities: []string{"create", "update"},
					Parameters: &PolicyParameters{
						Allowed:  []string{"allowed_val"},
						Denied:   []string{"denied_val"},
						Required: []string{"required_val"},
					},
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				"allowed_parameters",
				"denied_parameters",
				"required_parameters",
			},
		},
		{
			name: "cluster-scoped resource (empty namespace)",
			rules: []PolicyRule{
				{
					Path:         "secret/data/cluster/*",
					Capabilities: []string{"read"},
				},
			},
			namespace: "",
			resName:   "cluster-policy",
			want: []string{
				"# Kubernetes resource: cluster-policy (cluster-scoped)",
			},
			notWant: []string{
				"default/",
			},
		},
		{
			name: "deny capability",
			rules: []PolicyRule{
				{
					Path:         "secret/data/restricted/*",
					Capabilities: []string{"deny"},
					Description:  "Deny all access to restricted secrets",
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				`capabilities = ["deny"]`,
			},
		},
		{
			name:      "empty rules",
			rules:     []PolicyRule{},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				"# Vault policy managed by vault-access-operator",
				"# Kubernetes resource: default/my-app",
			},
		},
		{
			name: "empty parameters struct",
			rules: []PolicyRule{
				{
					Path:         "secret/data/app",
					Capabilities: []string{"read"},
					Parameters:   &PolicyParameters{},
				},
			},
			namespace: "default",
			resName:   "my-app",
			want: []string{
				`path "secret/data/app"`,
			},
			notWant: []string{
				"allowed_parameters",
				"denied_parameters",
				"required_parameters",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GeneratePolicyHCL(tt.rules, tt.namespace, tt.resName)

			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("GeneratePolicyHCL() missing expected content: %q\nGot:\n%s", want, got)
				}
			}

			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Errorf("GeneratePolicyHCL() contains unexpected content: %q\nGot:\n%s", notWant, got)
				}
			}
		})
	}
}

func TestGeneratePolicyHCLFormat(t *testing.T) {
	// Test that generated HCL follows proper format
	rules := []PolicyRule{
		{
			Path:         "secret/data/{{namespace}}/{{name}}/*",
			Capabilities: []string{"create", "read", "update", "delete", "list"},
			Description:  "Full access to app secrets",
			Parameters: &PolicyParameters{
				Allowed:  []string{"*"},
				Required: []string{"data"},
			},
		},
	}

	got := GeneratePolicyHCL(rules, "production", "my-app")

	// Verify structure
	lines := strings.Split(got, "\n")

	// Should start with header comment
	if !strings.HasPrefix(lines[0], "#") {
		t.Error("Policy should start with a comment")
	}

	// Should contain properly quoted path
	if !strings.Contains(got, `path "secret/data/production/my-app/*"`) {
		t.Error("Path should be properly quoted")
	}

	// Capabilities should be in array format with quotes
	if !strings.Contains(got, `capabilities = ["create", "read", "update", "delete", "list"]`) {
		t.Error("Capabilities should be in proper array format")
	}

	// Verify indentation (2 spaces for nested content)
	for _, line := range lines {
		if strings.HasPrefix(line, "  capabilities") || strings.HasPrefix(line, "  allowed") {
			// Good - proper indentation
		} else if strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "  ") {
			t.Errorf("Inconsistent indentation: %q", line)
		}
	}

	// Should end with closing brace
	trimmed := strings.TrimSpace(got)
	if !strings.HasSuffix(trimmed, "}") {
		t.Error("Policy should end with closing brace")
	}
}

func TestGeneratePolicyHCLMultipleCapabilityQuoting(t *testing.T) {
	rules := []PolicyRule{
		{
			Path:         "test/path",
			Capabilities: []string{"read", "list"},
		},
	}

	got := GeneratePolicyHCL(rules, "ns", "name")

	// Each capability should be individually quoted
	if !strings.Contains(got, `"read"`) {
		t.Error("Individual capabilities should be quoted")
	}
	if !strings.Contains(got, `"list"`) {
		t.Error("Individual capabilities should be quoted")
	}

	// Should be separated by comma and space
	if !strings.Contains(got, `"read", "list"`) {
		t.Error("Capabilities should be comma-separated")
	}
}

func TestPolicyRuleStruct(t *testing.T) {
	// Test that PolicyRule struct can be properly constructed
	rule := PolicyRule{
		Path:         "secret/data/test",
		Capabilities: []string{"read"},
		Description:  "Test rule",
		Parameters: &PolicyParameters{
			Allowed:  []string{"allow1"},
			Denied:   []string{"deny1"},
			Required: []string{"req1"},
		},
	}

	if rule.Path != "secret/data/test" {
		t.Errorf("PolicyRule.Path = %q, want %q", rule.Path, "secret/data/test")
	}
	if len(rule.Capabilities) != 1 || rule.Capabilities[0] != "read" {
		t.Errorf("PolicyRule.Capabilities = %v, want [read]", rule.Capabilities)
	}
	if rule.Description != "Test rule" {
		t.Errorf("PolicyRule.Description = %q, want %q", rule.Description, "Test rule")
	}
	if rule.Parameters == nil {
		t.Fatal("PolicyRule.Parameters should not be nil")
	}
	if len(rule.Parameters.Allowed) != 1 || rule.Parameters.Allowed[0] != "allow1" {
		t.Errorf("PolicyRule.Parameters.Allowed = %v, want [allow1]", rule.Parameters.Allowed)
	}
}

func BenchmarkGeneratePolicyHCL(b *testing.B) {
	rules := []PolicyRule{
		{
			Path:         "secret/data/{{namespace}}/{{name}}/*",
			Capabilities: []string{"create", "read", "update", "delete", "list"},
			Description:  "Full access to app secrets",
		},
		{
			Path:         "secret/metadata/{{namespace}}/{{name}}/*",
			Capabilities: []string{"list", "read"},
			Description:  "Read metadata",
		},
		{
			Path:         "auth/kubernetes/role/{{name}}",
			Capabilities: []string{"read"},
			Description:  "Read own role",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GeneratePolicyHCL(rules, "production-namespace", "my-application-service")
	}
}

func BenchmarkSubstituteVariables(b *testing.B) {
	path := "secret/data/{{namespace}}/{{name}}/{{namespace}}/{{name}}/*"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SubstituteVariables(path, "my-namespace", "my-application")
	}
}

func BenchmarkValidateCapabilities(b *testing.B) {
	caps := []string{"create", "read", "update", "delete", "list"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateCapabilities(caps)
	}
}
