package vault

import (
	"fmt"
	"strings"
)

// PolicyRule represents a single rule in a Vault policy
type PolicyRule struct {
	Path         string
	Capabilities []string
	Description  string
	Parameters   *PolicyParameters
}

// PolicyParameters represents parameter constraints for a policy rule
type PolicyParameters struct {
	Allowed  []string
	Denied   []string
	Required []string
}

// GeneratePolicyHCL generates an HCL policy document from rules
func GeneratePolicyHCL(rules []PolicyRule, namespace, name string) string {
	var builder strings.Builder

	// Add header comment
	builder.WriteString("# Vault policy managed by vault-access-operator\n")
	if namespace != "" {
		fmt.Fprintf(&builder, "# Kubernetes resource: %s/%s\n", namespace, name)
	} else {
		fmt.Fprintf(&builder, "# Kubernetes resource: %s (cluster-scoped)\n", name)
	}
	builder.WriteString("\n")

	for i, rule := range rules {
		// Substitute variables in path
		path := SubstituteVariables(rule.Path, namespace, name)

		// Add description as comment if present
		if rule.Description != "" {
			fmt.Fprintf(&builder, "# %s\n", rule.Description)
		}

		// Start path block
		fmt.Fprintf(&builder, "path %q {\n", path)

		// Write capabilities
		caps := make([]string, len(rule.Capabilities))
		for j, cap := range rule.Capabilities {
			caps[j] = fmt.Sprintf("%q", cap)
		}
		fmt.Fprintf(&builder, "  capabilities = [%s]\n", strings.Join(caps, ", "))

		// Write parameters if present
		if rule.Parameters != nil {
			if len(rule.Parameters.Allowed) > 0 || len(rule.Parameters.Denied) > 0 || len(rule.Parameters.Required) > 0 {
				builder.WriteString("\n")

				if len(rule.Parameters.Allowed) > 0 {
					allowed := make([]string, len(rule.Parameters.Allowed))
					for j, a := range rule.Parameters.Allowed {
						allowed[j] = fmt.Sprintf("%q", a)
					}
					fmt.Fprintf(&builder, "  allowed_parameters = {\n    \"*\" = [%s]\n  }\n", strings.Join(allowed, ", "))
				}

				if len(rule.Parameters.Denied) > 0 {
					denied := make([]string, len(rule.Parameters.Denied))
					for j, d := range rule.Parameters.Denied {
						denied[j] = fmt.Sprintf("%q", d)
					}
					fmt.Fprintf(&builder, "  denied_parameters = {\n    \"*\" = [%s]\n  }\n", strings.Join(denied, ", "))
				}

				if len(rule.Parameters.Required) > 0 {
					required := make([]string, len(rule.Parameters.Required))
					for j, r := range rule.Parameters.Required {
						required[j] = fmt.Sprintf("%q", r)
					}
					fmt.Fprintf(&builder, "  required_parameters = [%s]\n", strings.Join(required, ", "))
				}
			}
		}

		builder.WriteString("}\n")

		// Add newline between rules
		if i < len(rules)-1 {
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

// SubstituteVariables replaces template variables in a path
func SubstituteVariables(path, namespace, name string) string {
	result := path
	result = strings.ReplaceAll(result, "{{namespace}}", namespace)
	result = strings.ReplaceAll(result, "{{name}}", name)
	return result
}

// ValidateCapabilities checks if all capabilities are valid
func ValidateCapabilities(capabilities []string) error {
	validCaps := map[string]bool{
		"create": true,
		"read":   true,
		"update": true,
		"delete": true,
		"list":   true,
		"sudo":   true,
		"deny":   true,
	}

	hasDeny := false
	for _, cap := range capabilities {
		if !validCaps[cap] {
			return fmt.Errorf("invalid capability: %s", cap)
		}
		if cap == "deny" {
			hasDeny = true
		}
	}

	// deny cannot be combined with other capabilities
	if hasDeny && len(capabilities) > 1 {
		return fmt.Errorf("'deny' capability cannot be combined with other capabilities")
	}

	return nil
}

// ValidatePath checks if a path is valid
func ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Basic validation - more could be added
	if strings.Contains(path, "..") {
		return fmt.Errorf("path cannot contain '..'")
	}

	return nil
}

// ContainsNamespaceVariable checks if a path contains the {{namespace}} variable
func ContainsNamespaceVariable(path string) bool {
	return strings.Contains(path, "{{namespace}}")
}

// HasWildcardBeforeNamespace checks if a wildcard appears before the namespace variable
func HasWildcardBeforeNamespace(path string) bool {
	nsIdx := strings.Index(path, "{{namespace}}")
	if nsIdx == -1 {
		return false
	}

	wcIdx := strings.Index(path, "*")
	if wcIdx == -1 {
		return false
	}

	return wcIdx < nsIdx
}
