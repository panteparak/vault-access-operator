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
	"strings"
	"testing"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault/auth"
)

func TestAWSProvider_Applies(t *testing.T) {
	p := NewAWSProvider(nil)
	if !p.Applies(vaultv1alpha1.AuthConfig{AWS: &vaultv1alpha1.AWSAuth{}}) {
		t.Error("expected Applies true")
	}
	if p.Applies(vaultv1alpha1.AuthConfig{}) {
		t.Error("expected Applies false")
	}
}

func TestAWSProvider_UsesInjectedLoginDataGenerator(t *testing.T) {
	gen := func(_ context.Context, opts auth.AWSAuthOptions) (map[string]interface{}, error) {
		if opts.Role != "aws-role" {
			t.Errorf("expected role passed through, got %q", opts.Role)
		}
		return map[string]interface{}{"iam_http_request_method": "POST"}, nil
	}
	p := NewAWSProvider(gen)
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				AWS: &vaultv1alpha1.AWSAuth{
					Role:     "aws-role",
					AuthPath: "custom-aws",
					Region:   "us-east-1",
				},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.awsAuth.role != "aws-role" || vc.awsAuth.mountPath != "custom-aws" {
		t.Errorf("unexpected auth args: %+v", vc.awsAuth)
	}
	if vc.awsAuth.loginData["iam_http_request_method"] != "POST" {
		t.Errorf("expected generator login data to flow through, got %+v", vc.awsAuth.loginData)
	}
}

func TestAWSProvider_DefaultsMountPath(t *testing.T) {
	gen := func(_ context.Context, _ auth.AWSAuthOptions) (map[string]interface{}, error) {
		return map[string]interface{}{}, nil
	}
	p := NewAWSProvider(gen)
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{AWS: &vaultv1alpha1.AWSAuth{Role: "r"}},
		},
	}
	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.awsAuth.mountPath != "aws" {
		t.Errorf("expected default mountPath 'aws', got %q", vc.awsAuth.mountPath)
	}
}

func TestAWSProvider_WrapsGeneratorError(t *testing.T) {
	gen := func(_ context.Context, _ auth.AWSAuthOptions) (map[string]interface{}, error) {
		return nil, errors.New("sts boom")
	}
	p := NewAWSProvider(gen)
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{AWS: &vaultv1alpha1.AWSAuth{Role: "r"}},
		},
	}
	err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn)
	if err == nil || !strings.Contains(err.Error(), "failed to generate AWS login data") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}
