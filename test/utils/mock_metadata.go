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

package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// MockAWSIMDS creates a mock AWS Instance Metadata Service (IMDS) server.
// This is useful for testing AWS IAM authentication without actual EC2 instances.
type MockAWSIMDS struct {
	server *httptest.Server

	// Configuration
	Region           string
	AvailabilityZone string
	AccountID        string
	InstanceID       string
	RoleARN          string
	AccessKeyID      string
	SecretAccessKey  string
	SessionToken     string

	// IMDSv2 token management
	tokenMu    sync.RWMutex
	validToken string

	// Request tracking for test assertions
	RequestsMu sync.Mutex
	Requests   []MockIMDSRequest
}

// MockIMDSRequest records details of a request to the mock IMDS
type MockIMDSRequest struct {
	Path    string
	Method  string
	Headers http.Header
	Time    time.Time
}

// NewMockAWSIMDS creates and starts a new mock AWS IMDS server.
func NewMockAWSIMDS(region, availabilityZone string) *MockAWSIMDS {
	mock := &MockAWSIMDS{
		Region:           region,
		AvailabilityZone: availabilityZone,
		AccountID:        "123456789012",
		InstanceID:       "i-0123456789abcdef0",
		RoleARN:          "arn:aws:iam::123456789012:role/test-role",
		AccessKeyID:      "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:     "FwoGZXIvYXdzEE...",
		validToken:       "test-imds-token-12345",
		Requests:         make([]MockIMDSRequest, 0),
	}

	mock.server = httptest.NewServer(http.HandlerFunc(mock.handleRequest))
	return mock
}

// URL returns the base URL of the mock IMDS server.
func (m *MockAWSIMDS) URL() string {
	return m.server.URL
}

// Close shuts down the mock server.
func (m *MockAWSIMDS) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

// handleRequest processes incoming IMDS requests
func (m *MockAWSIMDS) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Record the request
	m.RequestsMu.Lock()
	m.Requests = append(m.Requests, MockIMDSRequest{
		Path:    r.URL.Path,
		Method:  r.Method,
		Headers: r.Header.Clone(),
		Time:    time.Now(),
	})
	m.RequestsMu.Unlock()

	path := r.URL.Path

	// IMDSv2 token endpoint
	if path == "/latest/api/token" && r.Method == "PUT" {
		m.handleTokenRequest(w, r)
		return
	}

	// Metadata endpoints (v2 requires token)
	if strings.HasPrefix(path, "/latest/meta-data/") {
		m.handleMetadataRequest(w, r)
		return
	}

	http.NotFound(w, r)
}

// handleTokenRequest handles IMDSv2 token requests
func (m *MockAWSIMDS) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Check for TTL header
	ttl := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
	if ttl == "" {
		http.Error(w, "Missing TTL header", http.StatusBadRequest)
		return
	}

	m.tokenMu.RLock()
	token := m.validToken
	m.tokenMu.RUnlock()

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

// handleMetadataRequest handles metadata requests
func (m *MockAWSIMDS) handleMetadataRequest(w http.ResponseWriter, r *http.Request) {
	// Check IMDSv2 token (optional - some paths work without it)
	token := r.Header.Get("X-aws-ec2-metadata-token")

	m.tokenMu.RLock()
	validToken := m.validToken
	m.tokenMu.RUnlock()

	// For this mock, we'll be lenient and allow requests without token
	// In production, IMDSv2 requires token for most requests
	_ = token
	_ = validToken

	path := strings.TrimPrefix(r.URL.Path, "/latest/meta-data/")

	switch path {
	case "placement/availability-zone":
		_, _ = w.Write([]byte(m.AvailabilityZone))

	case "placement/region":
		_, _ = w.Write([]byte(m.Region))

	case "instance-id":
		_, _ = w.Write([]byte(m.InstanceID))

	case "iam/info":
		info := map[string]interface{}{
			"Code":               "Success",
			"LastUpdated":        time.Now().Format(time.RFC3339),
			"InstanceProfileArn": fmt.Sprintf("arn:aws:iam::%s:instance-profile/test", m.AccountID),
			"InstanceProfileId":  "AIPATEST12345",
		}
		_ = json.NewEncoder(w).Encode(info)

	case "iam/security-credentials/":
		// List available roles
		_, _ = w.Write([]byte("test-role"))

	case "iam/security-credentials/test-role":
		creds := map[string]interface{}{
			"Code":            "Success",
			"LastUpdated":     time.Now().Format(time.RFC3339),
			"Type":            "AWS-HMAC",
			"AccessKeyId":     m.AccessKeyID,
			"SecretAccessKey": m.SecretAccessKey,
			"Token":           m.SessionToken,
			"Expiration":      time.Now().Add(6 * time.Hour).Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(creds)

	case "identity-document":
		doc := map[string]interface{}{
			"accountId":        m.AccountID,
			"architecture":     "x86_64",
			"availabilityZone": m.AvailabilityZone,
			"imageId":          "ami-12345678",
			"instanceId":       m.InstanceID,
			"instanceType":     "t3.medium",
			"pendingTime":      time.Now().Format(time.RFC3339),
			"privateIp":        "10.0.0.1",
			"region":           m.Region,
			"version":          "2017-09-30",
		}
		_ = json.NewEncoder(w).Encode(doc)

	default:
		http.NotFound(w, r)
	}
}

// MockGCPMetadata creates a mock GCP Compute Engine metadata server.
// This is useful for testing GCP IAM authentication without actual GCE instances.
type MockGCPMetadata struct {
	server *httptest.Server

	// Configuration
	ProjectID           string
	ProjectNumber       string
	Zone                string
	InstanceID          string
	InstanceName        string
	ServiceAccountEmail string
	IdentityToken       string

	// Request tracking
	RequestsMu sync.Mutex
	Requests   []MockGCPRequest
}

// MockGCPRequest records details of a request to the mock GCP metadata server
type MockGCPRequest struct {
	Path    string
	Method  string
	Headers http.Header
	Query   string
	Time    time.Time
}

// NewMockGCPMetadata creates and starts a new mock GCP metadata server.
func NewMockGCPMetadata(projectID, zone, email string) *MockGCPMetadata {
	mock := &MockGCPMetadata{
		ProjectID:           projectID,
		ProjectNumber:       "123456789012",
		Zone:                zone,
		InstanceID:          "1234567890123456789",
		InstanceName:        "test-instance",
		ServiceAccountEmail: email,
		IdentityToken:       "mock-identity-token.payload.signature",
		Requests:            make([]MockGCPRequest, 0),
	}

	mock.server = httptest.NewServer(http.HandlerFunc(mock.handleRequest))
	return mock
}

// URL returns the base URL of the mock GCP metadata server.
func (m *MockGCPMetadata) URL() string {
	return m.server.URL
}

// Close shuts down the mock server.
func (m *MockGCPMetadata) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

// handleRequest processes incoming GCP metadata requests
func (m *MockGCPMetadata) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Record the request
	m.RequestsMu.Lock()
	m.Requests = append(m.Requests, MockGCPRequest{
		Path:    r.URL.Path,
		Method:  r.Method,
		Headers: r.Header.Clone(),
		Query:   r.URL.RawQuery,
		Time:    time.Now(),
	})
	m.RequestsMu.Unlock()

	// Check for required Metadata-Flavor header
	flavor := r.Header.Get("Metadata-Flavor")
	if flavor != "Google" {
		http.Error(w, "Missing Metadata-Flavor: Google header", http.StatusForbidden)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/computeMetadata/v1/")

	switch {
	case path == "project/project-id":
		_, _ = w.Write([]byte(m.ProjectID))

	case path == "project/numeric-project-id":
		_, _ = w.Write([]byte(m.ProjectNumber))

	case path == "instance/zone":
		_, _ = fmt.Fprintf(w, "projects/%s/zones/%s", m.ProjectNumber, m.Zone)

	case path == "instance/id":
		_, _ = w.Write([]byte(m.InstanceID))

	case path == "instance/name":
		_, _ = w.Write([]byte(m.InstanceName))

	case path == "instance/service-accounts/default/email":
		if m.ServiceAccountEmail == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(m.ServiceAccountEmail))

	case path == "instance/service-accounts/default/token":
		token := map[string]interface{}{
			"access_token": "ya29.mock-access-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(token)

	case strings.HasPrefix(path, "instance/service-accounts/default/identity"):
		// Check for audience parameter
		audience := r.URL.Query().Get("audience")
		if audience == "" {
			http.Error(w, "audience parameter required", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(m.IdentityToken))

	case path == "instance/attributes/":
		_, _ = w.Write([]byte(""))

	case strings.HasPrefix(path, "instance/attributes/"):
		// Return empty for unknown attributes
		http.NotFound(w, r)

	default:
		http.NotFound(w, r)
	}
}

// SetIdentityToken sets the identity token returned for identity requests.
// This allows tests to provide custom JWTs for verification.
func (m *MockGCPMetadata) SetIdentityToken(token string) {
	m.IdentityToken = token
}

// SetServiceAccountEmail sets the service account email returned by the metadata server.
func (m *MockGCPMetadata) SetServiceAccountEmail(email string) {
	m.ServiceAccountEmail = email
}

// GetRequests returns a copy of the recorded requests for test assertions.
func (m *MockGCPMetadata) GetRequests() []MockGCPRequest {
	m.RequestsMu.Lock()
	defer m.RequestsMu.Unlock()
	requests := make([]MockGCPRequest, len(m.Requests))
	copy(requests, m.Requests)
	return requests
}

// ClearRequests clears the recorded requests.
func (m *MockGCPMetadata) ClearRequests() {
	m.RequestsMu.Lock()
	defer m.RequestsMu.Unlock()
	m.Requests = make([]MockGCPRequest, 0)
}

// GetRequests returns a copy of the recorded requests for test assertions.
func (m *MockAWSIMDS) GetRequests() []MockIMDSRequest {
	m.RequestsMu.Lock()
	defer m.RequestsMu.Unlock()
	requests := make([]MockIMDSRequest, len(m.Requests))
	copy(requests, m.Requests)
	return requests
}

// ClearRequests clears the recorded requests.
func (m *MockAWSIMDS) ClearRequests() {
	m.RequestsMu.Lock()
	defer m.RequestsMu.Unlock()
	m.Requests = make([]MockIMDSRequest, 0)
}
