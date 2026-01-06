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
						"client_token": "s.test-token-12345",
						"policies":     []string{"default"},
						"lease_duration": 3600,
					},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
		},
		{
			name: "server returns no auth",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{},
				}
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
				json.NewEncoder(w).Encode(response)
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
		if r.Method != "DELETE" {
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
				json.NewEncoder(w).Encode(response)
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
		json.NewEncoder(w).Encode(map[string]interface{}{
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
