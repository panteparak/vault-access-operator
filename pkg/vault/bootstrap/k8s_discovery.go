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

package bootstrap

import (
	"context"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
)

// Default paths for in-cluster Kubernetes configuration.
const (
	// ServiceAccountCAPath is the default path to the CA certificate.
	ServiceAccountCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// inClusterDiscovery implements K8sClusterDiscovery for in-cluster use.
type inClusterDiscovery struct {
	log logr.Logger
}

// NewInClusterDiscovery creates a new K8sClusterDiscovery for in-cluster use.
func NewInClusterDiscovery(log logr.Logger) K8sClusterDiscovery {
	return &inClusterDiscovery{
		log: log.WithName("k8s-discovery"),
	}
}

// GetClusterConfig returns the Kubernetes cluster configuration.
func (d *inClusterDiscovery) GetClusterConfig(ctx context.Context) (*KubernetesClusterConfig, error) {
	d.log.Info("discovering kubernetes cluster configuration")

	// Try to get in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	// Read CA certificate
	caCert, err := os.ReadFile(ServiceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from %s: %w", ServiceAccountCAPath, err)
	}

	result := &KubernetesClusterConfig{
		Host:   config.Host,
		CACert: string(caCert),
	}

	d.log.Info("discovered kubernetes cluster config",
		"host", result.Host,
		"caCertLength", len(result.CACert),
	)

	return result, nil
}

// Ensure inClusterDiscovery implements K8sClusterDiscovery.
var _ K8sClusterDiscovery = (*inClusterDiscovery)(nil)
