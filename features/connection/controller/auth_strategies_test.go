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

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// TestAuthStrategiesCoverAllConfiguredMethods makes sure the strategy table
// covers every AuthConfig sub-struct. If you add a new field to AuthConfig,
// this test fails unless you also add a corresponding entry in
// authStrategies. The old if/else chain had no such guard — adding a new
// auth method silently skipped the new method.
func TestAuthStrategiesCoverAllConfiguredMethods(t *testing.T) {
	cases := []struct {
		name string
		set  func(*vaultv1alpha1.AuthConfig)
	}{
		{"kubernetes", func(a *vaultv1alpha1.AuthConfig) { a.Kubernetes = &vaultv1alpha1.KubernetesAuth{} }},
		{"token", func(a *vaultv1alpha1.AuthConfig) { a.Token = &vaultv1alpha1.TokenAuth{} }},
		{"appRole", func(a *vaultv1alpha1.AuthConfig) { a.AppRole = &vaultv1alpha1.AppRoleAuth{} }},
		{"jwt", func(a *vaultv1alpha1.AuthConfig) { a.JWT = &vaultv1alpha1.JWTAuth{} }},
		{"oidc", func(a *vaultv1alpha1.AuthConfig) { a.OIDC = &vaultv1alpha1.OIDCAuth{} }},
		{"aws", func(a *vaultv1alpha1.AuthConfig) { a.AWS = &vaultv1alpha1.AWSAuth{} }},
		{"gcp", func(a *vaultv1alpha1.AuthConfig) { a.GCP = &vaultv1alpha1.GCPAuth{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := vaultv1alpha1.AuthConfig{}
			tc.set(&auth)
			matched := false
			for _, s := range authStrategies {
				if s.match(&auth) {
					matched = true
					if s.name != tc.name {
						t.Errorf("auth kind %q matched strategy %q", tc.name, s.name)
					}
				}
			}
			if !matched {
				t.Errorf("no strategy in authStrategies matched kind %q — new AuthConfig field not registered?", tc.name)
			}
		})
	}
}

// TestAuthStrategiesMatchersAreExclusive pins that each strategy matches a
// DIFFERENT configured sub-struct. Bootstrap is intentionally not a
// strategy — it's handled in isBootstrapRequired, upstream of authenticate.
func TestAuthStrategiesMatchersAreExclusive(t *testing.T) {
	for i, a := range authStrategies {
		for j, b := range authStrategies {
			if i == j {
				continue
			}
			// Build an AuthConfig that matches `a` and make sure `b` does not.
			authConfig := vaultv1alpha1.AuthConfig{}
			switch a.name {
			case "kubernetes":
				authConfig.Kubernetes = &vaultv1alpha1.KubernetesAuth{}
			case "token":
				authConfig.Token = &vaultv1alpha1.TokenAuth{}
			case "appRole":
				authConfig.AppRole = &vaultv1alpha1.AppRoleAuth{}
			case "jwt":
				authConfig.JWT = &vaultv1alpha1.JWTAuth{}
			case "oidc":
				authConfig.OIDC = &vaultv1alpha1.OIDCAuth{}
			case "aws":
				authConfig.AWS = &vaultv1alpha1.AWSAuth{}
			case "gcp":
				authConfig.GCP = &vaultv1alpha1.GCPAuth{}
			}
			if b.match(&authConfig) {
				t.Errorf("strategy %q matches AuthConfig for %q — matchers must be mutually exclusive", b.name, a.name)
			}
		}
	}
}
