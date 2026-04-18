/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"testing"
)

// TestNormalizeHCL_StripsHumanAddedComments pins the core §17 behavior:
// a user editing a Vault policy in the UI and adding `# managed by ops`
// must NOT trip drift every reconcile. Previously the normalizer only
// trimmed whitespace, so any comment made the stored HCL diverge from
// the operator-generated HCL forever.
func TestNormalizeHCL_StripsHumanAddedComments(t *testing.T) {
	h := &Handler{}

	generated := `path "secret/data/app/*" {
  capabilities = ["read"]
}`

	// Same policy content with a line comment added by a human.
	withLineComment := `# edited by ops on 2026-01-02
path "secret/data/app/*" {
  capabilities = ["read"]
}`

	// Same policy content with a C-style line comment.
	withSlashComment := `// edited by ops
path "secret/data/app/*" {
  capabilities = ["read"]
}`

	// Same policy content with a block comment wrapping the whole thing.
	withBlockComment := `/*
  This policy was created manually in the Vault UI.
*/
path "secret/data/app/*" {
  capabilities = ["read"]
}`

	// Inline comment after a real HCL line.
	withInlineComment := `path "secret/data/app/*" { # for the app SA
  capabilities = ["read"]
}`

	cases := map[string]string{
		"line comment":   withLineComment,
		"slash comment":  withSlashComment,
		"block comment":  withBlockComment,
		"inline comment": withInlineComment,
	}

	want := h.normalizeHCL(generated)
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := h.normalizeHCL(in)
			if got != want {
				t.Errorf("normalizeHCL with %s should match generated:\n  got:  %q\n  want: %q", name, got, want)
			}
		})
	}
}

// TestNormalizeHCL_PreservesPathGlobs is the regression test for the bug
// I introduced and fixed while implementing §17: `stripBlockComments` used
// to aggressively strip from any `/*` onward, truncating path globs like
// `secret/*`. The fix requires a matched `*/` before treating `/*` as a
// comment start.
func TestNormalizeHCL_PreservesPathGlobs(t *testing.T) {
	h := &Handler{}
	input := `path "secret/*" { capabilities = ["read"] }`

	got := h.normalizeHCL(input)

	// The exact output depends on our whitespace-collapsing rules, but
	// `secret/*` must survive intact.
	if !containsAll(got, `"secret/*"`, "capabilities", `"read"`) {
		t.Errorf("path glob was truncated by the comment stripper:\n  got: %q", got)
	}
}

// TestNormalizeHCL_CollapsesWhitespace ensures multiple spaces/tabs inside
// a single logical HCL line become one space. Different HCL formatters
// (Vault's internal writer, `terraform fmt`, hand-written) indent
// differently; semantically they're the same.
func TestNormalizeHCL_CollapsesWhitespace(t *testing.T) {
	h := &Handler{}
	tight := `path "x" { capabilities = ["read"] }`
	loose := `path   "x"   {   capabilities   =   ["read"]   }`
	tabs := "path\t\"x\"\t{\tcapabilities\t=\t[\"read\"]\t}"

	want := h.normalizeHCL(tight)
	for name, in := range map[string]string{"multi-space": loose, "tabs": tabs} {
		t.Run(name, func(t *testing.T) {
			if got := h.normalizeHCL(in); got != want {
				t.Errorf("whitespace variant should normalize to same output:\n  got:  %q\n  want: %q", got, want)
			}
		})
	}
}

// TestNormalizeHCL_StillDetectsSemanticDifferences is the negative test:
// two HCLs with different capabilities MUST compare unequal. Without this,
// drift detection would silently miss real changes.
func TestNormalizeHCL_StillDetectsSemanticDifferences(t *testing.T) {
	h := &Handler{}
	a := `path "x" { capabilities = ["read"] }`
	b := `path "x" { capabilities = ["read", "list"] }`

	if h.normalizeHCL(a) == h.normalizeHCL(b) {
		t.Error("normalizer should NOT equate policies with different capability lists")
	}
}

func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !contains(s, n) {
			return false
		}
	}
	return true
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) != -1
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
