/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Vault auth-method setup helpers used by the e2e suite. Each function is
// pure setup of ONE auth backend (kubernetes, jwt, oidc) — called from
// e2e_shared_infra_test.go during BeforeSuite. The Dex OAuth client lives
// here too because it's the natural counterpart of configureOIDCAuth.
//
// Why these are not in e2e_shared_infra_test.go: they're independent
// recipes — adding/changing one (e.g. enabling another auth backend)
// doesn't touch the infra orchestration. Splitting them keeps each
// concern auditable and reduces merge conflicts on backend additions.

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// ─────────────────────────────────────────────────────────────────────────────
// Kubernetes auth — Vault validates K8s SA tokens via TokenReview.
// ─────────────────────────────────────────────────────────────────────────────

// configureKubernetesAuth configures Vault's Kubernetes auth method at
// "auth/kubernetes". It retrieves the vault-auth SA token (which has
// TokenReview permissions) plus a combined CA bundle (TLS handshake +
// kubeconfig + ConfigMap), then writes them to auth/kubernetes/config so
// Vault can validate K8s SA tokens.
//
// Combined CA bundle handles k3s 1.25+ which uses separate server-ca and
// client-ca — only the server CA verifies kubernetes.default.svc but
// different sources may expose different CAs.
func configureKubernetesAuth() error {
	ctx := context.Background()

	reviewerJWT, err := utils.CreateServiceAccountTokenClientGo(
		ctx, vaultAuthNamespace, vaultAuthSA,
	)
	if err != nil {
		return fmt.Errorf("failed to get vault-auth SA token: %w", err)
	}

	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(GinkgoWriter, format+"\n", args...)
	}
	caCert, err := utils.BuildCABundle(ctx, logf)
	if err != nil {
		return fmt.Errorf("failed to build CA bundle: %w", err)
	}

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	// E2E_K8S_HOST overrides the Kubernetes API host that Vault uses.
	// When Vault runs external to k8s (docker-compose), it connects via
	// the docker network (e.g., https://k3s:6443) instead of in-cluster DNS.
	k8sHost := os.Getenv("E2E_K8S_HOST")
	if k8sHost == "" {
		k8sHost = "https://kubernetes.default.svc.cluster.local:443"
	}

	return vaultClient.WriteKubernetesAuthConfig(
		ctx, "kubernetes",
		k8sHost,
		strings.TrimSpace(reviewerJWT),
		strings.TrimSpace(caCert),
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// JWT auth — generic OIDC, used for K8s-SA-token-as-JWT and external issuers.
// ─────────────────────────────────────────────────────────────────────────────

// configureJWTAuth configures Vault's JWT auth method at the default
// "auth/jwt" path against the in-cluster K8s OIDC issuer.
func configureJWTAuth() error {
	return configureJWTAuthAtPath("auth/jwt")
}

// configureJWTAuthAtPath configures a JWT/OIDC auth method at the given
// Vault path against the K8s OIDC issuer.
//
// Strategy: build a combined CA bundle from all available sources (TLS
// handshake, kubeconfig, ConfigMap) and use it for OIDC discovery. This
// handles k3s 1.25+ which uses separate server-ca and client-ca — only
// the server CA can verify kubernetes.default.svc. Falls back to static
// JWKS PEM keys if no CA is available.
//
//nolint:unparam // authPath is parameterised for flexibility (jwt vs oidc)
func configureJWTAuthAtPath(authPath string) error {
	ctx := context.Background()

	issuer, err := fetchK8sOIDCIssuer(ctx)
	if err != nil {
		return err
	}

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}
	configPath := fmt.Sprintf("%s/config", authPath)

	if err := tryConfigureViaOIDCDiscovery(ctx, vaultClient, configPath, authPath, issuer); err == nil {
		return nil
	}
	return configureViaStaticJWKS(ctx, vaultClient, configPath, authPath, issuer)
}

// fetchK8sOIDCIssuer reads /.well-known/openid-configuration from the K8s
// API and returns the `issuer` claim. Used by both the OIDC-discovery and
// static-JWKS paths.
func fetchK8sOIDCIssuer(ctx context.Context) (string, error) {
	output, err := utils.GetK8sRawEndpoint(ctx, "/.well-known/openid-configuration")
	if err != nil {
		return "", fmt.Errorf("failed to get OIDC config: %w", err)
	}
	var oidcConfig struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(output, &oidcConfig); err != nil {
		return "", fmt.Errorf("failed to parse OIDC config: %w", err)
	}
	return oidcConfig.Issuer, nil
}

// tryConfigureViaOIDCDiscovery writes the JWT mount's config using
// oidc_discovery_url + a combined CA bundle. Returns an error (non-fatal)
// if either the CA bundle can't be built or the Vault write fails — caller
// is expected to fall back to static JWKS.
func tryConfigureViaOIDCDiscovery(
	ctx context.Context,
	vaultClient *utils.TestVaultClient,
	configPath, authPath, issuer string,
) error {
	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(GinkgoWriter, format+"\n", args...)
	}
	caBundle, err := utils.BuildCABundle(ctx, logf)
	if err != nil || caBundle == "" {
		fmt.Fprintf(GinkgoWriter, "Could not build CA bundle (%v), falling back to JWKS\n", err)
		return fmt.Errorf("no CA bundle: %w", err)
	}
	if err := vaultClient.WriteAuthConfig(ctx, configPath, map[string]interface{}{
		"oidc_discovery_url":    issuer,
		"bound_issuer":          issuer,
		"oidc_discovery_ca_pem": caBundle,
	}); err != nil {
		fmt.Fprintf(GinkgoWriter,
			"OIDC config write failed for %s (%v), falling back to JWKS\n",
			authPath, err,
		)
		return err
	}
	fmt.Fprintf(GinkgoWriter, "%s configured with OIDC discovery (CA bundle)\n", authPath)
	return nil
}

// configureViaStaticJWKS writes the JWT mount's config using PEM-encoded
// public keys extracted from K8s' JWKS endpoint. No CA negotiation needed.
func configureViaStaticJWKS(
	ctx context.Context,
	vaultClient *utils.TestVaultClient,
	configPath, authPath, issuer string,
) error {
	jwksOutput, err := utils.GetK8sRawEndpoint(ctx, "/openid/v1/jwks")
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}
	pemKeys, err := utils.JWKSToPEMKeys(jwksOutput)
	if err != nil {
		return fmt.Errorf("failed to convert JWKS to PEM keys: %w", err)
	}
	if err := vaultClient.WriteAuthConfig(ctx, configPath, map[string]interface{}{
		"jwt_validation_pubkeys": pemKeys,
		"bound_issuer":           issuer,
	}); err != nil {
		return fmt.Errorf("failed to configure %s with JWKS: %w", authPath, err)
	}
	fmt.Fprintf(GinkgoWriter, "%s configured with JWKS PEM keys\n", authPath)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// OIDC auth — JWT engine at auth/oidc pointed at Dex.
// ─────────────────────────────────────────────────────────────────────────────

// configureOIDCAuth configures Vault's JWT auth method at the "auth/oidc"
// mount path using Dex as the OIDC provider. Dex must be running on the
// host at dexDiscoveryURL.
func configureOIDCAuth() error {
	ctx := context.Background()

	if err := ensureDexReachable(); err != nil {
		return err
	}
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}
	if err := vaultClient.WriteAuthConfig(ctx, "auth/oidc/config", map[string]interface{}{
		"oidc_discovery_url": dexIssuer,
		"bound_issuer":       dexIssuer,
	}); err != nil {
		return fmt.Errorf("failed to configure OIDC auth with Dex: %w", err)
	}
	fmt.Fprintf(GinkgoWriter, "auth/oidc configured with Dex OIDC discovery (%s)\n", dexIssuer)
	return nil
}

// ensureDexReachable returns nil if Dex's discovery URL responds 200 OK,
// otherwise an error describing why. Used both as a precondition for
// configureOIDCAuth and (in skipIfDexUnreachable) as a Skip() guard.
func ensureDexReachable() error {
	resp, err := http.Get(dexDiscoveryURL) //nolint:gosec
	if err != nil {
		return fmt.Errorf("Dex not reachable at %s: %w", dexDiscoveryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Dex discovery returned status %d", resp.StatusCode)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Dex OAuth client — counterpart of configureOIDCAuth.
// ─────────────────────────────────────────────────────────────────────────────

// getDexToken obtains an id_token from Dex using the OAuth2 Resource Owner
// Password Credentials grant. The clientID determines the "aud" claim in
// the returned JWT — tests bind their Vault role's bound_audiences to it.
func getDexToken(clientID, clientSecret string) (string, error) {
	data := url.Values{
		"grant_type":    {"password"},
		"username":      {dexTestEmail},
		"password":      {dexTestPassword},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"openid email profile"},
	}
	resp, err := http.PostForm(dexTokenEndpoint, data)
	if err != nil {
		return "", fmt.Errorf("failed to request Dex token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read Dex response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Dex token request failed (status %d): %s", resp.StatusCode, body)
	}
	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse Dex token response: %w", err)
	}
	if tokenResp.IDToken == "" {
		return "", fmt.Errorf("empty id_token in Dex response")
	}
	return tokenResp.IDToken, nil
}
