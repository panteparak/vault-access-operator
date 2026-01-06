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

package controller

import (
	"errors"
	"testing"
	"time"
)

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		name             string
		config           RetryConfig
		retryCount       int
		expectedMin      time.Duration
		expectedMax      time.Duration
		checkExponential bool
	}{
		{
			name: "first retry (retryCount=0) returns initial delay",
			config: RetryConfig{
				InitialDelay: 5 * time.Second,
				MaxDelay:     30 * time.Minute,
				Multiplier:   2.0,
				JitterFactor: 0,
				MaxRetries:   0,
			},
			retryCount:  0,
			expectedMin: 5 * time.Second,
			expectedMax: 5 * time.Second,
		},
		{
			name: "negative retry count returns initial delay",
			config: RetryConfig{
				InitialDelay: 5 * time.Second,
				MaxDelay:     30 * time.Minute,
				Multiplier:   2.0,
				JitterFactor: 0,
				MaxRetries:   0,
			},
			retryCount:  -1,
			expectedMin: 5 * time.Second,
			expectedMax: 5 * time.Second,
		},
		{
			name: "second retry (retryCount=1) doubles delay",
			config: RetryConfig{
				InitialDelay: 5 * time.Second,
				MaxDelay:     30 * time.Minute,
				Multiplier:   2.0,
				JitterFactor: 0,
				MaxRetries:   0,
			},
			retryCount:  1,
			expectedMin: 10 * time.Second,
			expectedMax: 10 * time.Second,
		},
		{
			name: "third retry (retryCount=2) quadruples delay",
			config: RetryConfig{
				InitialDelay: 5 * time.Second,
				MaxDelay:     30 * time.Minute,
				Multiplier:   2.0,
				JitterFactor: 0,
				MaxRetries:   0,
			},
			retryCount:  2,
			expectedMin: 20 * time.Second,
			expectedMax: 20 * time.Second,
		},
		{
			name: "delay capped at MaxDelay",
			config: RetryConfig{
				InitialDelay: 5 * time.Second,
				MaxDelay:     1 * time.Minute,
				Multiplier:   2.0,
				JitterFactor: 0,
				MaxRetries:   0,
			},
			retryCount:  10, // Would be 5s * 2^10 = 5120s without cap
			expectedMin: 1 * time.Minute,
			expectedMax: 1 * time.Minute,
		},
		{
			name: "with jitter, delay is within expected range",
			config: RetryConfig{
				InitialDelay: 10 * time.Second,
				MaxDelay:     30 * time.Minute,
				Multiplier:   2.0,
				JitterFactor: 0.1, // +/- 10%
				MaxRetries:   0,
			},
			retryCount:  1,                                     // Base delay = 20s
			expectedMin: 18 * time.Second,                      // 20s - 10% = 18s
			expectedMax: 22*time.Second + 100*time.Millisecond, // 20s + 10% = 22s (with small buffer)
		},
		{
			name: "jitter does not reduce below initial delay",
			config: RetryConfig{
				InitialDelay: 5 * time.Second,
				MaxDelay:     30 * time.Minute,
				Multiplier:   2.0,
				JitterFactor: 0.5, // Large jitter
				MaxRetries:   0,
			},
			retryCount:  0,
			expectedMin: 5 * time.Second, // Should not go below initial
			expectedMax: 7*time.Second + 500*time.Millisecond,
		},
		{
			name: "custom multiplier (3x)",
			config: RetryConfig{
				InitialDelay: 1 * time.Second,
				MaxDelay:     1 * time.Hour,
				Multiplier:   3.0,
				JitterFactor: 0,
				MaxRetries:   0,
			},
			retryCount:  2,
			expectedMin: 9 * time.Second, // 1s * 3^2 = 9s
			expectedMax: 9 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run multiple times to account for jitter randomness
			iterations := 1
			if tt.config.JitterFactor > 0 {
				iterations = 100
			}

			for i := 0; i < iterations; i++ {
				got := tt.config.CalculateBackoff(tt.retryCount)

				if got < tt.expectedMin {
					t.Errorf("CalculateBackoff() = %v, want >= %v", got, tt.expectedMin)
				}
				if got > tt.expectedMax {
					t.Errorf("CalculateBackoff() = %v, want <= %v", got, tt.expectedMax)
				}
			}
		})
	}
}

func TestCalculateBackoff_ExponentialGrowth(t *testing.T) {
	config := RetryConfig{
		InitialDelay: 1 * time.Second,
		MaxDelay:     1 * time.Hour,
		Multiplier:   2.0,
		JitterFactor: 0, // No jitter for deterministic test
		MaxRetries:   0,
	}

	// Verify exponential growth: delay = InitialDelay * Multiplier^retryCount
	expectedDelays := []time.Duration{
		1 * time.Second,  // 1 * 2^0 = 1
		2 * time.Second,  // 1 * 2^1 = 2
		4 * time.Second,  // 1 * 2^2 = 4
		8 * time.Second,  // 1 * 2^3 = 8
		16 * time.Second, // 1 * 2^4 = 16
		32 * time.Second, // 1 * 2^5 = 32
	}

	for retryCount, expected := range expectedDelays {
		got := config.CalculateBackoff(retryCount)
		if got != expected {
			t.Errorf("CalculateBackoff(%d) = %v, want %v", retryCount, got, expected)
		}
	}
}

func TestCalculateBackoff_JitterDistribution(t *testing.T) {
	config := RetryConfig{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Hour,
		Multiplier:   2.0,
		JitterFactor: 0.1, // +/- 10%
		MaxRetries:   0,
	}

	retryCount := 3 // Base delay = 100ms * 2^3 = 800ms
	baseDelay := 800 * time.Millisecond

	// Run many iterations to verify jitter distribution
	iterations := 1000
	var minSeen, maxSeen time.Duration
	minSeen = time.Hour // Start with large value
	maxSeen = 0

	for i := 0; i < iterations; i++ {
		got := config.CalculateBackoff(retryCount)
		if got < minSeen {
			minSeen = got
		}
		if got > maxSeen {
			maxSeen = got
		}
	}

	// Verify that we see values across the jitter range
	expectedMin := time.Duration(float64(baseDelay) * 0.9) // -10%
	expectedMax := time.Duration(float64(baseDelay) * 1.1) // +10%

	// With 1000 iterations, we should see values near both extremes
	// Allow some margin for statistical variation
	if minSeen > time.Duration(float64(baseDelay)*0.95) {
		t.Errorf("Jitter not applied correctly: minSeen = %v, expected near %v", minSeen, expectedMin)
	}
	if maxSeen < time.Duration(float64(baseDelay)*1.05) {
		t.Errorf("Jitter not applied correctly: maxSeen = %v, expected near %v", maxSeen, expectedMax)
	}
}

func TestShouldRetry(t *testing.T) {
	defaultConfig := RetryConfig{
		InitialDelay: 5 * time.Second,
		MaxDelay:     30 * time.Minute,
		Multiplier:   2.0,
		JitterFactor: 0,
		MaxRetries:   0, // Unlimited
	}

	limitedConfig := RetryConfig{
		InitialDelay: 5 * time.Second,
		MaxDelay:     30 * time.Minute,
		Multiplier:   2.0,
		JitterFactor: 0,
		MaxRetries:   3, // Limited to 3 retries
	}

	tests := []struct {
		name               string
		err                error
		currentRetryCount  int
		config             RetryConfig
		expectedRequeue    bool
		expectedGiveUp     bool
		expectedRetryCount int
		checkDelay         bool
		expectedDelay      time.Duration
	}{
		{
			name:               "nil error - no retry",
			err:                nil,
			currentRetryCount:  0,
			config:             defaultConfig,
			expectedRequeue:    false,
			expectedGiveUp:     false,
			expectedRetryCount: 0,
		},
		{
			name:               "transient error - should retry",
			err:                NewTransientError("temporary failure", nil),
			currentRetryCount:  0,
			config:             defaultConfig,
			expectedRequeue:    true,
			expectedGiveUp:     false,
			expectedRetryCount: 1,
			checkDelay:         true,
			expectedDelay:      5 * time.Second,
		},
		{
			name:               "connection not ready - should retry",
			err:                NewConnectionNotReadyError("vault-conn", "initializing"),
			currentRetryCount:  2,
			config:             defaultConfig,
			expectedRequeue:    true,
			expectedGiveUp:     false,
			expectedRetryCount: 3,
			checkDelay:         true,
			expectedDelay:      20 * time.Second, // 5s * 2^2
		},
		{
			name:               "policy not found - should retry",
			err:                NewPolicyNotFoundError("VaultPolicyBinding", "my-policy", "default"),
			currentRetryCount:  1,
			config:             defaultConfig,
			expectedRequeue:    true,
			expectedGiveUp:     false,
			expectedRetryCount: 2,
			checkDelay:         true,
			expectedDelay:      10 * time.Second, // 5s * 2^1
		},
		{
			name:               "conflict error - no retry (give up)",
			err:                NewConflictError("policy", "my-policy", "already exists"),
			currentRetryCount:  0,
			config:             defaultConfig,
			expectedRequeue:    false,
			expectedGiveUp:     true,
			expectedRetryCount: 0,
		},
		{
			name:               "validation error - no retry (give up)",
			err:                NewValidationError("spec.policies", "at least one policy required"),
			currentRetryCount:  0,
			config:             defaultConfig,
			expectedRequeue:    false,
			expectedGiveUp:     true,
			expectedRetryCount: 0,
		},
		{
			name:               "max retries not exceeded - should retry",
			err:                NewTransientError("temporary failure", nil),
			currentRetryCount:  2,
			config:             limitedConfig,
			expectedRequeue:    true,
			expectedGiveUp:     false,
			expectedRetryCount: 3,
		},
		{
			name:               "max retries exceeded - give up",
			err:                NewTransientError("temporary failure", nil),
			currentRetryCount:  3,
			config:             limitedConfig,
			expectedRequeue:    false,
			expectedGiveUp:     true,
			expectedRetryCount: 4,
		},
		{
			name:               "error with timeout pattern - should retry",
			err:                errors.New("operation timeout"),
			currentRetryCount:  0,
			config:             defaultConfig,
			expectedRequeue:    true,
			expectedGiveUp:     false,
			expectedRetryCount: 1,
		},
		{
			name:               "error with connection refused pattern - should retry",
			err:                errors.New("dial tcp: connection refused"),
			currentRetryCount:  0,
			config:             defaultConfig,
			expectedRequeue:    true,
			expectedGiveUp:     false,
			expectedRetryCount: 1,
		},
		{
			name:               "error with rate limit pattern - should retry",
			err:                errors.New("rate limit exceeded"),
			currentRetryCount:  0,
			config:             defaultConfig,
			expectedRequeue:    true,
			expectedGiveUp:     false,
			expectedRetryCount: 1,
		},
		{
			name:               "unknown error - no retry (give up)",
			err:                errors.New("some unknown error"),
			currentRetryCount:  0,
			config:             defaultConfig,
			expectedRequeue:    false,
			expectedGiveUp:     true, // Non-retryable errors cause give up
			expectedRetryCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldRetry(tt.err, tt.currentRetryCount, tt.config)

			if result.Requeue != tt.expectedRequeue {
				t.Errorf("ShouldRetry().Requeue = %v, want %v", result.Requeue, tt.expectedRequeue)
			}
			if result.GiveUp != tt.expectedGiveUp {
				t.Errorf("ShouldRetry().GiveUp = %v, want %v", result.GiveUp, tt.expectedGiveUp)
			}
			if result.RetryCount != tt.expectedRetryCount {
				t.Errorf("ShouldRetry().RetryCount = %v, want %v", result.RetryCount, tt.expectedRetryCount)
			}
			if tt.checkDelay && result.RequeueAfter != tt.expectedDelay {
				t.Errorf("ShouldRetry().RequeueAfter = %v, want %v", result.RequeueAfter, tt.expectedDelay)
			}
		})
	}
}

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.InitialDelay != InitialRetryDelay {
		t.Errorf("DefaultRetryConfig().InitialDelay = %v, want %v", config.InitialDelay, InitialRetryDelay)
	}
	if config.MaxDelay != MaxRetryDelay {
		t.Errorf("DefaultRetryConfig().MaxDelay = %v, want %v", config.MaxDelay, MaxRetryDelay)
	}
	if config.Multiplier != BackoffMultiplier {
		t.Errorf("DefaultRetryConfig().Multiplier = %v, want %v", config.Multiplier, BackoffMultiplier)
	}
	if config.JitterFactor != JitterFactor {
		t.Errorf("DefaultRetryConfig().JitterFactor = %v, want %v", config.JitterFactor, JitterFactor)
	}
	if config.MaxRetries != MaxRetryCount {
		t.Errorf("DefaultRetryConfig().MaxRetries = %v, want %v", config.MaxRetries, MaxRetryCount)
	}
}

func TestResetRetryCount(t *testing.T) {
	result := ResetRetryCount()

	if result.Requeue {
		t.Error("ResetRetryCount().Requeue = true, want false")
	}
	if result.RetryCount != 0 {
		t.Errorf("ResetRetryCount().RetryCount = %v, want 0", result.RetryCount)
	}
	if result.GiveUp {
		t.Error("ResetRetryCount().GiveUp = true, want false")
	}
}

func TestRequeueImmediately(t *testing.T) {
	result := RequeueImmediately()

	if !result.Requeue {
		t.Error("RequeueImmediately().Requeue = false, want true")
	}
	if result.RequeueAfter != 0 {
		t.Errorf("RequeueImmediately().RequeueAfter = %v, want 0", result.RequeueAfter)
	}
	if result.RetryCount != 0 {
		t.Errorf("RequeueImmediately().RetryCount = %v, want 0", result.RetryCount)
	}
}

func TestRequeueAfter(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{
			name:     "short duration",
			duration: 5 * time.Second,
		},
		{
			name:     "long duration",
			duration: 30 * time.Minute,
		},
		{
			name:     "zero duration",
			duration: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RequeueAfter(tt.duration)

			if !result.Requeue {
				t.Error("RequeueAfter().Requeue = false, want true")
			}
			if result.RequeueAfter != tt.duration {
				t.Errorf("RequeueAfter().RequeueAfter = %v, want %v", result.RequeueAfter, tt.duration)
			}
			if result.RetryCount != 0 {
				t.Errorf("RequeueAfter().RetryCount = %v, want 0", result.RetryCount)
			}
		})
	}
}

func TestCalculateNextRetryTime(t *testing.T) {
	config := RetryConfig{
		InitialDelay: 5 * time.Second,
		MaxDelay:     30 * time.Minute,
		Multiplier:   2.0,
		JitterFactor: 0,
		MaxRetries:   0,
	}

	tests := []struct {
		name          string
		now           time.Time
		retryCount    int
		expectedDelay time.Duration
	}{
		{
			name:          "first retry",
			now:           time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			retryCount:    0,
			expectedDelay: 5 * time.Second,
		},
		{
			name:          "third retry",
			now:           time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			retryCount:    2,
			expectedDelay: 20 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedTime := tt.now.Add(tt.expectedDelay)
			got := CalculateNextRetryTime(tt.now, tt.retryCount, config)

			if !got.Equal(expectedTime) {
				t.Errorf("CalculateNextRetryTime() = %v, want %v", got, expectedTime)
			}
		})
	}
}
