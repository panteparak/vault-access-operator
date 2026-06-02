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

// Ginkgo lifecycle entry points for the e2e suite. This file owns the
// suite-level hooks (BeforeSuite, AfterSuite, ReportAfterEach) and nothing
// else — config lives in e2e_config_test.go, the operator policy in
// e2e_operator_policy_test.go, infra setup in e2e_shared_infra_test.go,
// and per-backend auth config in e2e_vault_auth_setup_test.go.

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// TestE2E is the Ginkgo entry point. Both local and CI use docker-compose
// (k3s + Vault + Dex) with identical Makefile targets. In CI, E2E_SKIP_BUILD
// and E2E_SKIP_IMAGE_LOAD are set to use pre-built images. Webhooks use
// self-signed TLS certificates instead of cert-manager.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting vault-access-operator integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	utils.TimedBy(fmt.Sprintf(
		"using image: %s (skipBuild=%v, skipImageLoad=%v)",
		projectImage, skipBuild, skipImageLoad,
	))

	if !skipBuild {
		buildOperatorImage()
	} else {
		utils.TimedBy("skipping image build (E2E_SKIP_BUILD=true)")
	}

	if !skipImageLoad {
		loadOperatorImageIntoCluster()
	} else {
		utils.TimedBy("skipping image load (E2E_SKIP_IMAGE_LOAD=true)")
	}

	configureGinkgoTimeouts()
	setupSharedTestInfrastructure()
})

var _ = AfterSuite(func() {
	cleanupSharedTestInfrastructure()
})

// ReportAfterEach captures debugging context when a spec fails: operator
// logs, Vault health, CRD status, recent warning/error events. Output goes
// to GinkgoWriter so it lands in the spec's failure report rather than
// being swallowed by Ginkgo's quiet mode.
var _ = ReportAfterEach(func(report SpecReport) {
	if !report.Failed() {
		return
	}
	writeFailureHeader(report)
	dumpOperatorLogs()
	dumpVaultHealth()
	dumpCRDStatus()
	dumpRecentWarningEvents()
	fmt.Fprintf(GinkgoWriter, "=== END FAILURE CONTEXT ===\n\n")
})

// ─────────────────────────────────────────────────────────────────────────────
// BeforeSuite helpers
// ─────────────────────────────────────────────────────────────────────────────

func buildOperatorImage() {
	utils.TimedBy("building the manager(Operator) image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")
}

func loadOperatorImageIntoCluster() {
	utils.TimedBy("loading the manager(Operator) image into cluster")
	err := utils.LoadImageToCluster(projectImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		"Failed to load the manager(Operator) image into cluster")
}

func configureGinkgoTimeouts() {
	SetDefaultEventuallyTimeout(defaultTimeout)
	SetDefaultEventuallyPollingInterval(defaultPollingInterval)
	if isCI {
		utils.TimedBy(fmt.Sprintf(
			"running in CI mode with extended timeouts (%v)", defaultTimeout,
		))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportAfterEach helpers — keep the hook itself declarative.
// ─────────────────────────────────────────────────────────────────────────────

func writeFailureHeader(report SpecReport) {
	fmt.Fprintf(GinkgoWriter, "\n=== FAILURE CONTEXT ===\n")
	fmt.Fprintf(GinkgoWriter, "Test: %s\n", report.FullText())
	fmt.Fprintf(GinkgoWriter, "Duration: %v\n", report.RunTime)
	fmt.Fprintf(GinkgoWriter, "Failure: %s\n", report.FailureMessage())
}

func dumpOperatorLogs() {
	cmd := exec.Command("kubectl", "logs",
		"-n", "vault-access-operator-system",
		"-l", "control-plane=controller-manager",
		"--tail=50",
	)
	output, err := utils.Run(cmd)
	if err != nil {
		fmt.Fprintf(GinkgoWriter, "\n--- Failed to get Operator Logs: %v ---\n", err)
		return
	}
	fmt.Fprintf(GinkgoWriter, "\n--- Operator Logs (last 50 lines) ---\n%s\n", output)
}

func dumpVaultHealth() {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}
	cmd := exec.Command("curl", "-sf", vaultAddr+"/v1/sys/health")
	output, err := utils.Run(cmd)
	if err != nil {
		fmt.Fprintf(GinkgoWriter, "\n--- Failed to get Vault Health: %v ---\n", err)
		return
	}
	fmt.Fprintf(GinkgoWriter, "\n--- Vault Health ---\n%s\n", output)
}

func dumpCRDStatus() {
	crdTypes := "vaultconnections,vaultpolicies,vaultroles,vaultclusterpolicies,vaultclusterroles"
	crdColumns := "KIND:.kind,NAMESPACE:.metadata.namespace,NAME:.metadata.name," +
		"PHASE:.status.phase,MESSAGE:.status.message"
	cmd := exec.Command("kubectl", "get", crdTypes, "-A", "-o", "custom-columns="+crdColumns)
	output, err := utils.Run(cmd)
	if err != nil {
		fmt.Fprintf(GinkgoWriter, "\n--- Failed to get CRD Status: %v ---\n", err)
		return
	}
	fmt.Fprintf(GinkgoWriter, "\n--- CRD Status ---\n%s\n", output)
}

func dumpRecentWarningEvents() {
	eventColumns := "NAMESPACE:.metadata.namespace,TYPE:.type,REASON:.reason,MESSAGE:.message"
	cmd := exec.Command("kubectl", "get", "events", "-A",
		"--sort-by=.lastTimestamp",
		"--field-selector=type!=Normal",
		"-o", "custom-columns="+eventColumns,
	)
	if output, err := utils.Run(cmd); err == nil {
		fmt.Fprintf(GinkgoWriter, "\n--- Recent Warning/Error Events ---\n%s\n", output)
	}
}
