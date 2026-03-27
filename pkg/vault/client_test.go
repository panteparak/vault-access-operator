package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const httpMethodDelete = "DELETE"

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  ClientConfig
		wantErr bool
	}{
		{
			name: "valid config with address only",
			config: ClientConfig{
				Address: "http://localhost:8200",
			},
			wantErr: false,
		},
		{
			name: "valid config with timeout",
			config: ClientConfig{
				Address: "http://localhost:8200",
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "valid config with TLS skip verify",
			config: ClientConfig{
				Address: "https://localhost:8200",
				TLSConfig: &TLSConfig{
					SkipVerify: true,
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with nil TLS",
			config: ClientConfig{
				Address:   "http://localhost:8200",
				TLSConfig: nil,
			},
			wantErr: false,
		},
		{
			name: "empty address uses default",
			config: ClientConfig{
				Address: "",
			},
			wantErr: false, // Vault client accepts empty address and uses default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client without error")
			}
		})
	}
}

func TestNewClientWithInvalidTLS(t *testing.T) {
	// Test with non-existent CA cert file
	config := ClientConfig{
		Address: "https://localhost:8200",
		TLSConfig: &TLSConfig{
			CACert: "/nonexistent/path/to/ca.crt",
		},
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() expected error for non-existent CA cert, got nil")
	}
}

func TestClientConnectionName(t *testing.T) {
	client, err := NewClient(ClientConfig{Address: "http://localhost:8200"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Test initial state
	if got := client.ConnectionName(); got != "" {
		t.Errorf("ConnectionName() = %q, want empty string", got)
	}

	// Test setting connection name
	expectedName := "my-vault-connection"
	client.SetConnectionName(expectedName)
	if got := client.ConnectionName(); got != expectedName {
		t.Errorf("ConnectionName() = %q, want %q", got, expectedName)
	}
}

func TestClientAuthentication(t *testing.T) {
	client, err := NewClient(ClientConfig{Address: "http://localhost:8200"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Test initial state
	if client.IsAuthenticated() {
		t.Error("IsAuthenticated() = true, want false initially")
	}

	// Test setting authenticated
	client.SetAuthenticated(true)
	if !client.IsAuthenticated() {
		t.Error("IsAuthenticated() = false, want true after SetAuthenticated(true)")
	}

	// Test unsetting authenticated
	client.SetAuthenticated(false)
	if client.IsAuthenticated() {
		t.Error("IsAuthenticated() = true, want false after SetAuthenticated(false)")
	}
}

func TestAuthenticateToken(t *testing.T) {
	client, err := NewClient(ClientConfig{Address: "http://localhost:8200"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "valid token",
			token:   "s.abcdef12345",
			wantErr: false,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset client state
			client.SetAuthenticated(false)
			client.SetToken("")

			err := client.AuthenticateToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthenticateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if !client.IsAuthenticated() {
					t.Error("IsAuthenticated() = false after successful AuthenticateToken()")
				}
				if got := client.Token(); got != tt.token {
					t.Errorf("Token() = %q, want %q", got, tt.token)
				}
			}
		})
	}
}

func TestAuthenticateKubernetesTokenNotFound(t *testing.T) {
	client, err := NewClient(ClientConfig{Address: "http://localhost:8200"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()

	// Test with non-existent token path
	err = client.AuthenticateKubernetes(ctx, "my-role", "kubernetes", "/nonexistent/token/path")
	if err == nil {
		t.Error("AuthenticateKubernetes() expected error for non-existent token, got nil")
	}
}

func TestAuthenticateKubernetesWithMockServer(t *testing.T) {
	// Create a temporary token file
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	testJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
	if err := os.WriteFile(tokenPath, []byte(testJWT), 0600); err != nil {
		t.Fatalf("Failed to write test token: %v", err)
	}

	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		wantErr        bool
	}{
		{
			name: "successful authentication",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/auth/kubernetes/login" {
					t.Errorf("Unexpected path: %s", r.URL.Path)
				}
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "s.test-token-12345",
						"policies":       []string{"default"},
						"lease_duration": 3600,
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
		},
		{
			name: "server returns no auth",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantErr: true,
		},
		{
			name: "server returns error",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				response := map[string]interface{}{
					"errors": []string{"permission denied"},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			ctx := context.Background()
			err = client.AuthenticateKubernetes(ctx, "my-role", "kubernetes", tokenPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthenticateKubernetes() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && !client.IsAuthenticated() {
				t.Error("Client should be authenticated after successful login")
			}
		})
	}
}

func TestAuthenticateAppRoleWithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		roleID         string
		secretID       string
		mountPath      string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		wantErr        bool
	}{
		{
			name:      "successful authentication",
			roleID:    "test-role-id",
			secretID:  "test-secret-id",
			mountPath: "",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/auth/approle/login" {
					t.Errorf("Unexpected path: %s, expected /v1/auth/approle/login", r.URL.Path)
				}
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "s.test-approle-token",
						"policies":       []string{"default", "app-policy"},
						"lease_duration": 3600,
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
		},
		{
			name:      "custom mount path",
			roleID:    "test-role-id",
			secretID:  "test-secret-id",
			mountPath: "custom-approle",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/auth/custom-approle/login" {
					t.Errorf("Unexpected path: %s, expected /v1/auth/custom-approle/login", r.URL.Path)
				}
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token": "s.test-approle-token",
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
		},
		{
			name:      "server returns no auth",
			roleID:    "test-role-id",
			secretID:  "test-secret-id",
			mountPath: "",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantErr: true,
		},
		{
			name:      "invalid credentials",
			roleID:    "invalid-role",
			secretID:  "invalid-secret",
			mountPath: "",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				response := map[string]interface{}{
					"errors": []string{"invalid role or secret ID"},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			ctx := context.Background()
			err = client.AuthenticateAppRole(ctx, tt.roleID, tt.secretID, tt.mountPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthenticateAppRole() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && !client.IsAuthenticated() {
				t.Error("Client should be authenticated after successful login")
			}
		})
	}
}

type authRequestTestCase struct {
	name              string
	mountPath         string
	expectedPath      string
	expectedBody      map[string]string
	serverStatusCode  int
	serverResponse    map[string]interface{}
	wantErr           bool
	wantAuthenticated bool
}

func runAuthWithMockServerTests(
	t *testing.T,
	methodName string,
	tests []authRequestTestCase,
	authenticate func(context.Context, *Client, authRequestTestCase) error,
) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedPath string
			var receivedBody map[string]interface{}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
					t.Fatalf("failed to decode request body: %v", err)
				}
				w.WriteHeader(tt.serverStatusCode)
				_ = json.NewEncoder(w).Encode(tt.serverResponse)
			}))
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			err = authenticate(context.Background(), client, tt)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s() error = %v, wantErr %v", methodName, err, tt.wantErr)
			}

			if receivedPath != tt.expectedPath {
				t.Errorf("%s() path = %q, want %q", methodName, receivedPath, tt.expectedPath)
			}

			for key, want := range tt.expectedBody {
				if got, ok := receivedBody[key].(string); !ok || got != want {
					t.Errorf("%s() body[%q] = %v, want %q", methodName, key, receivedBody[key], want)
				}
			}

			if client.IsAuthenticated() != tt.wantAuthenticated {
				t.Errorf("IsAuthenticated() = %v, want %v", client.IsAuthenticated(), tt.wantAuthenticated)
			}
		})
	}
}

func newTokenAuthRequestTestCases(authMethod string, tokenValue string, clientToken string) []authRequestTestCase {
	defaultPath := "/v1/auth/" + authMethod + "/login"
	customMountPath := "custom-" + authMethod
	customPath := "/v1/auth/" + customMountPath + "/login"

	return []authRequestTestCase{
		{
			name:         "successful authentication with default mount path",
			mountPath:    "",
			expectedPath: defaultPath,
			expectedBody: map[string]string{
				"role": "test-role",
				"jwt":  tokenValue,
			},
			serverStatusCode: http.StatusOK,
			serverResponse: map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": clientToken,
				},
			},
			wantAuthenticated: true,
		},
		{
			name:         "successful authentication with custom mount path",
			mountPath:    customMountPath,
			expectedPath: customPath,
			expectedBody: map[string]string{
				"role": "test-role",
				"jwt":  tokenValue,
			},
			serverStatusCode: http.StatusOK,
			serverResponse: map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": clientToken,
				},
			},
			wantAuthenticated: true,
		},
		{
			name:         "server returns no auth",
			mountPath:    "",
			expectedPath: defaultPath,
			expectedBody: map[string]string{
				"role": "test-role",
				"jwt":  tokenValue,
			},
			serverStatusCode: http.StatusOK,
			serverResponse: map[string]interface{}{
				"data": map[string]interface{}{},
			},
			wantErr: true,
		},
		{
			name:         "server returns error",
			mountPath:    "",
			expectedPath: defaultPath,
			expectedBody: map[string]string{
				"role": "test-role",
				"jwt":  tokenValue,
			},
			serverStatusCode: http.StatusUnauthorized,
			serverResponse: map[string]interface{}{
				"errors": []string{"permission denied"},
			},
			wantErr: true,
		},
	}
}

func newAWSAuthRequestTestCases() []authRequestTestCase {
	return []authRequestTestCase{
		{
			name:         "successful authentication with default mount path",
			mountPath:    "",
			expectedPath: "/v1/auth/aws/login",
			expectedBody: map[string]string{
				"role":                    "test-role",
				"iam_http_request_method": "POST",
				"iam_request_url":         "https://sts.amazonaws.com/",
			},
			serverStatusCode: http.StatusOK,
			serverResponse: map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "s.test-aws-token",
				},
			},
			wantAuthenticated: true,
		},
		{
			name:         "successful authentication with custom mount path",
			mountPath:    "custom-aws",
			expectedPath: "/v1/auth/custom-aws/login",
			expectedBody: map[string]string{
				"role":                    "test-role",
				"iam_http_request_method": "POST",
			},
			serverStatusCode: http.StatusOK,
			serverResponse: map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "s.test-aws-token",
				},
			},
			wantAuthenticated: true,
		},
		{
			name:         "server returns no auth",
			mountPath:    "",
			expectedPath: "/v1/auth/aws/login",
			expectedBody: map[string]string{
				"role":                    "test-role",
				"iam_http_request_method": "POST",
			},
			serverStatusCode: http.StatusOK,
			serverResponse: map[string]interface{}{
				"data": map[string]interface{}{},
			},
			wantErr: true,
		},
		{
			name:         "server returns error",
			mountPath:    "",
			expectedPath: "/v1/auth/aws/login",
			expectedBody: map[string]string{
				"role":                    "test-role",
				"iam_http_request_method": "POST",
			},
			serverStatusCode: http.StatusUnauthorized,
			serverResponse: map[string]interface{}{
				"errors": []string{"permission denied"},
			},
			wantErr: true,
		},
	}
}

func TestAuthenticateJWTWithMockServer(t *testing.T) {
	runAuthWithMockServerTests(
		t,
		"AuthenticateJWT",
		newTokenAuthRequestTestCases("jwt", "test-jwt", "s.test-jwt-token"),
		func(ctx context.Context, client *Client, tt authRequestTestCase) error {
			return client.AuthenticateJWT(ctx, "test-role", tt.mountPath, "test-jwt")
		},
	)
}

func TestAuthenticateOIDCWithMockServer(t *testing.T) {
	runAuthWithMockServerTests(
		t,
		"AuthenticateOIDC",
		newTokenAuthRequestTestCases("oidc", "test-jwt", "s.test-oidc-token"),
		func(ctx context.Context, client *Client, tt authRequestTestCase) error {
			return client.AuthenticateOIDC(ctx, "test-role", tt.mountPath, "test-jwt")
		},
	)
}

func TestAuthenticateAWSWithMockServer(t *testing.T) {
	runAuthWithMockServerTests(
		t,
		"AuthenticateAWS",
		newAWSAuthRequestTestCases(),
		func(ctx context.Context, client *Client, tt authRequestTestCase) error {
			loginData := make(map[string]interface{}, len(tt.expectedBody)-1)
			for key, value := range tt.expectedBody {
				if key == "role" {
					continue
				}
				loginData[key] = value
			}

			return client.AuthenticateAWS(ctx, "test-role", tt.mountPath, loginData)
		},
	)
}

func TestAuthenticateAWSMutatesLoginDataWithRole(t *testing.T) {
	loginData := map[string]interface{}{
		"iam_http_request_method": "POST",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token": "s.test-aws-token",
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	err = client.AuthenticateAWS(context.Background(), "test-role", "", loginData)
	if err != nil {
		t.Fatalf("AuthenticateAWS() error = %v", err)
	}

	if got, ok := loginData["role"].(string); !ok || got != "test-role" {
		t.Errorf("AuthenticateAWS() loginData role = %v, want %q", loginData["role"], "test-role")
	}
}

func TestAuthenticateGCPWithMockServer(t *testing.T) {
	runAuthWithMockServerTests(
		t,
		"AuthenticateGCP",
		newTokenAuthRequestTestCases("gcp", "signed-jwt", "s.test-gcp-token"),
		func(ctx context.Context, client *Client, tt authRequestTestCase) error {
			return client.AuthenticateGCP(ctx, "test-role", tt.mountPath, "signed-jwt")
		},
	)
}

func TestIsHealthy(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		wantHealthy    bool
		wantErr        bool
	}{
		{
			name: "healthy vault",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				// The Vault client uses query parameters to control status codes
				// We return 200 for healthy vault
				response := map[string]interface{}{
					"initialized": true,
					"sealed":      false,
					"version":     "1.13.0",
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantHealthy: true,
			wantErr:     false,
		},
		{
			name: "sealed vault - returns 200 with sealed=true",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				// The Vault client with the query params will still get 200
				// but we return sealed=true in the body
				response := map[string]interface{}{
					"initialized": true,
					"sealed":      true,
					"version":     "1.13.0",
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantHealthy: false,
			wantErr:     false,
		},
		{
			name: "uninitialized vault - returns 200 with initialized=false",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"initialized": false,
					"sealed":      true,
					"version":     "1.13.0",
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantHealthy: false,
			wantErr:     false,
		},
		{
			name: "server returns error",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantHealthy: false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			ctx := context.Background()
			healthy, err := client.IsHealthy(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsHealthy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && healthy != tt.wantHealthy {
				t.Errorf("IsHealthy() = %v, want %v", healthy, tt.wantHealthy)
			}
		})
	}
}

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		wantVersion    string
		wantErr        bool
	}{
		{
			name: "returns version",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"initialized": true,
					"sealed":      false,
					"version":     "1.15.2",
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantVersion: "1.15.2",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			ctx := context.Background()
			version, err := client.GetVersion(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if version != tt.wantVersion {
				t.Errorf("GetVersion() = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestKubernetesAuthRolePaths(t *testing.T) {
	tests := []struct {
		name         string
		authPath     string
		roleName     string
		expectedPath string
	}{
		{
			name:         "default auth path",
			authPath:     "",
			roleName:     "my-role",
			expectedPath: "/v1/auth/kubernetes/role/my-role",
		},
		{
			name:         "custom auth path",
			authPath:     "auth/custom-k8s",
			roleName:     "custom-role",
			expectedPath: "/v1/auth/custom-k8s/role/custom-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"bound_service_account_names":      []string{"*"},
						"bound_service_account_namespaces": []string{"*"},
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			ctx := context.Background()
			_, _ = client.ReadKubernetesAuthRole(ctx, tt.authPath, tt.roleName)

			if receivedPath != tt.expectedPath {
				t.Errorf("ReadKubernetesAuthRole() path = %q, want %q", receivedPath, tt.expectedPath)
			}
		})
	}
}

func TestWriteKubernetesAuthRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" && r.Method != "POST" {
			t.Errorf("Expected PUT or POST method, got %s", r.Method)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}

		// Verify expected fields
		if _, ok := body["bound_service_account_names"]; !ok {
			t.Error("Expected bound_service_account_names in request body")
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	data := map[string]interface{}{
		"bound_service_account_names":      []string{"my-sa"},
		"bound_service_account_namespaces": []string{"my-namespace"},
		"policies":                         []string{"my-policy"},
		"ttl":                              "1h",
	}

	err = client.WriteKubernetesAuthRole(ctx, "", "test-role", data)
	if err != nil {
		t.Errorf("WriteKubernetesAuthRole() error = %v", err)
	}
}

func TestDeleteKubernetesAuthRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != httpMethodDelete {
			t.Errorf("Expected DELETE method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.DeleteKubernetesAuthRole(ctx, "", "test-role")
	if err != nil {
		t.Errorf("DeleteKubernetesAuthRole() error = %v", err)
	}
}

func TestKubernetesAuthRoleExists(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		wantExists     bool
		wantErr        bool
	}{
		{
			name: "role exists",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"bound_service_account_names": []string{"*"},
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			wantExists: true,
			wantErr:    false,
		},
		{
			name: "role does not exist",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantExists: false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			ctx := context.Background()
			exists, err := client.KubernetesAuthRoleExists(ctx, "", "test-role")
			if (err != nil) != tt.wantErr {
				t.Errorf("KubernetesAuthRoleExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if exists != tt.wantExists {
				t.Errorf("KubernetesAuthRoleExists() = %v, want %v", exists, tt.wantExists)
			}
		})
	}
}

func TestClientTimeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"initialized": true,
			"sealed":      false,
		})
	}))
	defer server.Close()

	// Create client with very short timeout
	client, err := NewClient(ClientConfig{
		Address: server.URL,
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	_, err = client.IsHealthy(ctx)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

func TestUpdateKubernetesAuthConfig(t *testing.T) {
	var receivedPath string
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.UpdateKubernetesAuthConfig(ctx, "kubernetes", "new-jwt-token")
	if err != nil {
		t.Errorf("UpdateKubernetesAuthConfig() error = %v", err)
	}

	expectedPath := "/v1/auth/kubernetes/config"
	if receivedPath != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, receivedPath)
	}

	jwt, ok := receivedBody["token_reviewer_jwt"].(string)
	if !ok || jwt != "new-jwt-token" {
		t.Errorf("expected token_reviewer_jwt = %q, got %v", "new-jwt-token", receivedBody["token_reviewer_jwt"])
	}

	// Verify only token_reviewer_jwt is sent (merge-update semantics)
	if len(receivedBody) != 1 {
		t.Errorf("expected only 1 field in body (token_reviewer_jwt), got %d: %v", len(receivedBody), receivedBody)
	}
}

func TestHandleAuthResponse_CapturesAccessor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "s.test-token",
				"accessor":       "accessor-12345",
				"policies":       []string{"default"},
				"lease_duration": 3600,
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.AuthenticateKubernetesWithToken(ctx, "test-role", "kubernetes", "fake-jwt")
	if err != nil {
		t.Fatalf("AuthenticateKubernetesWithToken() error = %v", err)
	}

	if got := client.TokenAccessor(); got != "accessor-12345" {
		t.Errorf("TokenAccessor() = %q, want %q", got, "accessor-12345")
	}
}

func TestDisableAuth(t *testing.T) {
	var receivedPath string
	var receivedMethod string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.DisableAuth(ctx, "kubernetes")
	if err != nil {
		t.Errorf("DisableAuth() error = %v", err)
	}

	expectedPath := "/v1/sys/auth/kubernetes"
	if receivedPath != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, receivedPath)
	}

	if receivedMethod != httpMethodDelete {
		t.Errorf("expected DELETE method, got %s", receivedMethod)
	}
}

func TestWritePolicy_Success(t *testing.T) {
	var receivedPath string
	var receivedMethod string
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.WritePolicy(ctx, "my-policy", `path "secret/*" { capabilities = ["read"] }`)
	if err != nil {
		t.Errorf("WritePolicy() error = %v", err)
	}

	expectedPath := "/v1/sys/policies/acl/my-policy"
	if receivedPath != expectedPath {
		t.Errorf("WritePolicy() path = %q, want %q", receivedPath, expectedPath)
	}
	if receivedMethod != "PUT" {
		t.Errorf("WritePolicy() method = %q, want PUT", receivedMethod)
	}
	if policy, ok := receivedBody["policy"].(string); !ok || policy != `path "secret/*" { capabilities = ["read"] }` {
		t.Errorf("WritePolicy() body policy = %v, want HCL string", receivedBody["policy"])
	}
}

func TestWritePolicy_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"internal server error"},
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.WritePolicy(ctx, "my-policy", `path "secret/*" { capabilities = ["read"] }`)
	if err == nil {
		t.Error("WritePolicy() expected error for server 500, got nil")
	}
}

func TestReadPolicy_Success(t *testing.T) {
	expectedHCL := `path "secret/*" { capabilities = ["read"] }`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"request_id": "test-request-id",
			"data": map[string]interface{}{
				"name":   "my-policy",
				"policy": expectedHCL,
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	policy, err := client.ReadPolicy(ctx, "my-policy")
	if err != nil {
		t.Errorf("ReadPolicy() error = %v", err)
	}
	if policy != expectedHCL {
		t.Errorf("ReadPolicy() = %q, want %q", policy, expectedHCL)
	}
}

func TestReadPolicy_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	policy, err := client.ReadPolicy(ctx, "nonexistent-policy")
	if err != nil {
		t.Errorf("ReadPolicy() error = %v, want nil for not found", err)
	}
	if policy != "" {
		t.Errorf("ReadPolicy() = %q, want empty string for not found", policy)
	}
}

func TestDeletePolicy_Success(t *testing.T) {
	var receivedPath string
	var receivedMethod string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.DeletePolicy(ctx, "my-policy")
	if err != nil {
		t.Errorf("DeletePolicy() error = %v", err)
	}

	expectedPath := "/v1/sys/policies/acl/my-policy"
	if receivedPath != expectedPath {
		t.Errorf("DeletePolicy() path = %q, want %q", receivedPath, expectedPath)
	}
	if receivedMethod != httpMethodDelete {
		t.Errorf("DeletePolicy() method = %q, want DELETE", receivedMethod)
	}
}

func TestDeletePolicy_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"internal server error"},
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.DeletePolicy(ctx, "my-policy")
	if err == nil {
		t.Error("DeletePolicy() expected error for server 500, got nil")
	}
}

func TestPolicyExists_True(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"policies": []string{"default", "my-policy", "root"},
				"keys":     []string{"default", "my-policy", "root"},
			},
			"policies": []string{"default", "my-policy", "root"},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	exists, err := client.PolicyExists(ctx, "my-policy")
	if err != nil {
		t.Errorf("PolicyExists() error = %v", err)
	}
	if !exists {
		t.Error("PolicyExists() = false, want true")
	}
}

func TestPolicyExists_False(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"policies": []string{"default", "root"},
				"keys":     []string{"default", "root"},
			},
			"policies": []string{"default", "root"},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	exists, err := client.PolicyExists(ctx, "nonexistent-policy")
	if err != nil {
		t.Errorf("PolicyExists() error = %v", err)
	}
	if exists {
		t.Error("PolicyExists() = true, want false")
	}
}

func TestListPolicies_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"policies": []string{"default", "my-policy", "root"},
				"keys":     []string{"default", "my-policy", "root"},
			},
			"policies": []string{"default", "my-policy", "root"},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	policies, err := client.ListPolicies(ctx)
	if err != nil {
		t.Errorf("ListPolicies() error = %v", err)
	}

	expected := []string{"default", "my-policy", "root"}
	if len(policies) != len(expected) {
		t.Fatalf("ListPolicies() returned %d policies, want %d", len(policies), len(expected))
	}
	for i, p := range policies {
		if p != expected[i] {
			t.Errorf("ListPolicies()[%d] = %q, want %q", i, p, expected[i])
		}
	}
}

func TestListPolicies_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"policies": []string{},
				"keys":     []string{},
			},
			"policies": []string{},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	policies, err := client.ListPolicies(ctx)
	if err != nil {
		t.Errorf("ListPolicies() error = %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("ListPolicies() returned %d policies, want 0", len(policies))
	}
}

func TestRenewSelf_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/renew-self" {
			t.Errorf("RenewSelf() path = %q, want /v1/auth/token/renew-self", r.URL.Path)
		}
		response := map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "s.renewed-token",
				"policies":       []string{"default"},
				"lease_duration": 7200,
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client.SetToken("s.original-token")

	ctx := context.Background()
	beforeRenew := time.Now()
	err = client.RenewSelf(ctx)
	if err != nil {
		t.Errorf("RenewSelf() error = %v", err)
	}

	expectedTTL := 7200 * time.Second
	if client.TokenTTL() != expectedTTL {
		t.Errorf("TokenTTL() = %v, want %v", client.TokenTTL(), expectedTTL)
	}

	// Token expiration should be approximately now + 7200s
	if client.TokenExpiration().Before(beforeRenew.Add(expectedTTL - time.Second)) {
		t.Errorf("TokenExpiration() = %v, expected around %v", client.TokenExpiration(), beforeRenew.Add(expectedTTL))
	}
}
