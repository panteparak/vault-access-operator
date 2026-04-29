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
	"fmt"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault/token"
)

// fakeAuthenticator records calls to each Authenticate* method so that
// provider tests can assert on the exact method invoked, the role,
// mount path, and payload.
type fakeAuthenticator struct {
	tokenAuth struct {
		called bool
		token  string
	}
	k8sAuth struct {
		called               bool
		role, mountPath, jwt string
		failWith             error
	}
	appRoleAuth struct {
		called                      bool
		roleID, secretID, mountPath string
	}
	jwtAuth struct {
		called               bool
		role, mountPath, jwt string
	}
	oidcAuth struct {
		called               bool
		role, mountPath, jwt string
	}
	awsAuth struct {
		called          bool
		role, mountPath string
		loginData       map[string]interface{}
	}
	gcpAuth struct {
		called                     bool
		role, mountPath, signedJWT string
	}
	forceErr error
}

func (f *fakeAuthenticator) AuthenticateToken(t string) error {
	if f.forceErr != nil {
		return f.forceErr
	}
	f.tokenAuth.called = true
	f.tokenAuth.token = t
	return nil
}

func (f *fakeAuthenticator) AuthenticateKubernetesWithToken(_ context.Context, role, mountPath, jwt string) error {
	if f.forceErr != nil {
		return f.forceErr
	}
	if f.k8sAuth.failWith != nil {
		return f.k8sAuth.failWith
	}
	f.k8sAuth.called = true
	f.k8sAuth.role = role
	f.k8sAuth.mountPath = mountPath
	f.k8sAuth.jwt = jwt
	return nil
}

func (f *fakeAuthenticator) AuthenticateAppRole(_ context.Context, roleID, secretID, mountPath string) error {
	if f.forceErr != nil {
		return f.forceErr
	}
	f.appRoleAuth.called = true
	f.appRoleAuth.roleID = roleID
	f.appRoleAuth.secretID = secretID
	f.appRoleAuth.mountPath = mountPath
	return nil
}

func (f *fakeAuthenticator) AuthenticateJWT(_ context.Context, role, mountPath, jwt string) error {
	if f.forceErr != nil {
		return f.forceErr
	}
	f.jwtAuth.called = true
	f.jwtAuth.role = role
	f.jwtAuth.mountPath = mountPath
	f.jwtAuth.jwt = jwt
	return nil
}

func (f *fakeAuthenticator) AuthenticateOIDC(_ context.Context, role, mountPath, jwt string) error {
	if f.forceErr != nil {
		return f.forceErr
	}
	f.oidcAuth.called = true
	f.oidcAuth.role = role
	f.oidcAuth.mountPath = mountPath
	f.oidcAuth.jwt = jwt
	return nil
}

func (f *fakeAuthenticator) AuthenticateAWS(
	_ context.Context, role, mountPath string, loginData map[string]interface{},
) error {
	if f.forceErr != nil {
		return f.forceErr
	}
	f.awsAuth.called = true
	f.awsAuth.role = role
	f.awsAuth.mountPath = mountPath
	f.awsAuth.loginData = loginData
	return nil
}

func (f *fakeAuthenticator) AuthenticateGCP(_ context.Context, role, mountPath, signedJWT string) error {
	if f.forceErr != nil {
		return f.forceErr
	}
	f.gcpAuth.called = true
	f.gcpAuth.role = role
	f.gcpAuth.mountPath = mountPath
	f.gcpAuth.signedJWT = signedJWT
	return nil
}

// fakeSecretReader resolves SecretKeySelector references from an in-memory
// map keyed by "namespace/name/key".
type fakeSecretReader struct {
	data map[string]string
	err  error
}

func (f *fakeSecretReader) GetSecretData(_ context.Context, ref *vaultv1alpha1.SecretKeySelector) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	key := fmt.Sprintf("%s/%s/%s", ref.Namespace, ref.Name, ref.Key)
	v, ok := f.data[key]
	if !ok {
		return "", fmt.Errorf("secret %s not found", key)
	}
	return v, nil
}

// fakeTokenProvider returns a fixed token for GetToken, or an error if configured.
type fakeTokenProvider struct {
	token string
	err   error
}

func (f *fakeTokenProvider) GetToken(_ context.Context, _ token.GetTokenOptions) (*token.TokenInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &token.TokenInfo{Token: f.token}, nil
}
