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
	"math"
	"math/rand"
	"time"
)

const (
	// InitialRetryDelay is the initial delay before the first retry
	InitialRetryDelay = 5 * time.Second

	// MaxRetryDelay is the maximum delay between retries
	MaxRetryDelay = 30 * time.Minute

	// BackoffMultiplier is the factor by which the delay increases
	BackoffMultiplier = 2.0

	// JitterFactor is the maximum random jitter as a fraction of the delay
	JitterFactor = 0.1

	// MaxRetryCount is the maximum number of retries before giving up
	// Set to 0 for unlimited retries
	MaxRetryCount = 0
)

// RetryConfig holds configuration for retry behavior
type RetryConfig struct {
	// InitialDelay is the initial delay before the first retry
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration

	// Multiplier is the factor by which the delay increases
	Multiplier float64

	// JitterFactor is the maximum random jitter as a fraction of the delay
	JitterFactor float64

	// MaxRetries is the maximum number of retries (0 for unlimited)
	MaxRetries int
}

// DefaultRetryConfig returns the default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		InitialDelay: InitialRetryDelay,
		MaxDelay:     MaxRetryDelay,
		Multiplier:   BackoffMultiplier,
		JitterFactor: JitterFactor,
		MaxRetries:   MaxRetryCount,
	}
}

// CalculateBackoff calculates the backoff duration for a given retry count
func (c RetryConfig) CalculateBackoff(retryCount int) time.Duration {
	if retryCount <= 0 {
		return c.InitialDelay
	}

	// Calculate exponential backoff
	delay := float64(c.InitialDelay) * math.Pow(c.Multiplier, float64(retryCount))

	// Cap at max delay
	if delay > float64(c.MaxDelay) {
		delay = float64(c.MaxDelay)
	}

	// Add jitter
	if c.JitterFactor > 0 {
		jitter := delay * c.JitterFactor * (2*rand.Float64() - 1) // Random value between -JitterFactor and +JitterFactor
		delay += jitter
	}

	// Ensure we don't go below initial delay
	if delay < float64(c.InitialDelay) {
		delay = float64(c.InitialDelay)
	}

	return time.Duration(delay)
}

// RetryResult represents the result of a retry decision
type RetryResult struct {
	// Requeue indicates whether the request should be requeued
	Requeue bool

	// RequeueAfter is the duration to wait before requeuing
	RequeueAfter time.Duration

	// RetryCount is the updated retry count
	RetryCount int

	// GiveUp indicates whether to stop retrying
	GiveUp bool
}

// ShouldRetry determines whether and when to retry based on the error
func ShouldRetry(err error, currentRetryCount int, config RetryConfig) RetryResult {
	// If no error, don't retry
	if err == nil {
		return RetryResult{
			Requeue:    false,
			RetryCount: 0,
		}
	}

	// If the error is not retryable, don't retry
	if !IsRetryableError(err) {
		return RetryResult{
			Requeue:    false,
			RetryCount: currentRetryCount,
			GiveUp:     true,
		}
	}

	// Check if we've exceeded max retries
	newRetryCount := currentRetryCount + 1
	if config.MaxRetries > 0 && newRetryCount > config.MaxRetries {
		return RetryResult{
			Requeue:    false,
			RetryCount: newRetryCount,
			GiveUp:     true,
		}
	}

	// Calculate backoff delay
	delay := config.CalculateBackoff(currentRetryCount)

	return RetryResult{
		Requeue:      true,
		RequeueAfter: delay,
		RetryCount:   newRetryCount,
		GiveUp:       false,
	}
}

// ResetRetryCount returns a RetryResult that resets the retry count
func ResetRetryCount() RetryResult {
	return RetryResult{
		Requeue:    false,
		RetryCount: 0,
		GiveUp:     false,
	}
}

// RequeueImmediately returns a RetryResult that requeues immediately
func RequeueImmediately() RetryResult {
	return RetryResult{
		Requeue:      true,
		RequeueAfter: 0,
		RetryCount:   0,
	}
}

// RequeueAfter returns a RetryResult that requeues after a specified duration
func RequeueAfter(duration time.Duration) RetryResult {
	return RetryResult{
		Requeue:      true,
		RequeueAfter: duration,
		RetryCount:   0,
	}
}

// CalculateNextRetryTime calculates the next retry time based on current time and retry count
func CalculateNextRetryTime(now time.Time, retryCount int, config RetryConfig) time.Time {
	delay := config.CalculateBackoff(retryCount)
	return now.Add(delay)
}
