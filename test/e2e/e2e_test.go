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

package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "vault-access-operator-system"

// metricsRoleBindingName is the name of the RBAC
// that will be created to allow get the metrics data
const metricsRoleBindingName = "vault-access-operator-metrics-binding"

// serviceAccountName and metricsServiceName differ between
// Helm and kustomize deployments.
// Defaults are for kustomize (local dev); overridden in
// BeforeAll for Helm (CI).
var (
	serviceAccountName = "vault-access-operator-controller-manager"
	metricsServiceName = "vault-access-operator-controller-manager-metrics-service"
)

var _ = Describe("Manager", Ordered, Label("setup"), func() {
	var controllerPodName string

	// operatorAlreadyDeployed tracks whether the operator
	// was pre-deployed by CI. If true, we skip setup and
	// cleanup to avoid conflicts with other tests.
	var operatorAlreadyDeployed bool

	ctx := context.Background()

	// Before running the tests, set up the environment by
	// creating the namespace, enforcing the restricted
	// security policy, installing CRDs, and deploying the
	// controller.
	BeforeAll(func() {
		// Check if operator is already deployed
		// (CI deploys it before running tests)
		utils.TimedBy(
			"checking if operator is already deployed",
		)
		k8sClient, err := utils.GetK8sClient()
		Expect(err).NotTo(HaveOccurred())

		var deployList appsv1.DeploymentList
		err = k8sClient.List(ctx, &deployList,
			client.InNamespace(namespace),
			client.MatchingLabels{
				"control-plane": "controller-manager",
			},
		)
		if err == nil && len(deployList.Items) > 0 {
			utils.TimedBy(
				"operator already deployed by CI, " +
					"skipping setup",
			)
			operatorAlreadyDeployed = true
			// Helm uses different resource names
			// than kustomize
			serviceAccountName = "vault-access-operator"
			metricsServiceName =
				"vault-access-operator-metrics"
			return
		}

		// Operator not deployed, set up from scratch
		// (local development)
		utils.TimedBy("creating manager namespace")
		err = utils.CreateNamespace(ctx, namespace)
		Expect(err).NotTo(HaveOccurred(),
			"Failed to create namespace",
		)

		utils.TimedBy(
			"labeling the namespace to enforce " +
				"the restricted security policy",
		)
		err = utils.LabelNamespace(ctx, namespace,
			map[string]string{
				"pod-security.kubernetes.io/enforce": "restricted",
			},
		)
		Expect(err).NotTo(HaveOccurred(),
			"Failed to label namespace "+
				"with restricted policy",
		)

		utils.TimedBy("installing CRDs")
		cmd := exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(),
			"Failed to install CRDs",
		)

		utils.TimedBy("deploying the controller-manager")
		cmd = exec.Command("make", "deploy",
			fmt.Sprintf("IMG=%s", projectImage),
		)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(),
			"Failed to deploy the controller-manager",
		)
	})

	// After all tests have been executed, clean up by
	// undeploying the controller, uninstalling CRDs,
	// and deleting the namespace. Skip cleanup if
	// operator was pre-deployed by CI.
	AfterAll(func() {
		utils.TimedBy(
			"cleaning up the curl pod for metrics",
		)
		_ = utils.DeleteObject(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "curl-metrics",
				Namespace: namespace,
			},
		})

		// Skip cleanup if operator was pre-deployed
		// by CI (other tests depend on it)
		if operatorAlreadyDeployed {
			utils.TimedBy(
				"skipping cleanup - operator was " +
					"pre-deployed by CI",
			)
			return
		}

		utils.TimedBy(
			"undeploying the controller-manager",
		)
		cmd := exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		utils.TimedBy("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		utils.TimedBy("removing manager namespace")
		_ = utils.DeleteNamespace(ctx, namespace)
	})

	// After each test, check for failures and collect
	// logs, events, and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			utils.TimedBy(
				"Fetching controller manager pod logs",
			)
			cmd := exec.Command("kubectl", "logs",
				controllerPodName, "-n", namespace,
			)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter,
					"Controller logs:\n %s",
					controllerLogs,
				)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter,
					"Failed to get Controller logs: %s",
					err,
				)
			}

			utils.TimedBy(
				"Fetching Kubernetes events",
			)
			cmd = exec.Command("kubectl", "get",
				"events", "-n", namespace,
				"--sort-by=.lastTimestamp",
			)
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter,
					"Kubernetes events:\n%s",
					eventsOutput,
				)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter,
					"Failed to get Kubernetes events: %s",
					err,
				)
			}

			utils.TimedBy(
				"Fetching curl-metrics logs",
			)
			cmd = exec.Command("kubectl", "logs",
				"curl-metrics", "-n", namespace,
			)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter,
					"Metrics logs:\n %s",
					metricsOutput,
				)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter,
					"Failed to get curl-metrics "+
						"logs: %s",
					err,
				)
			}

			utils.TimedBy(
				"Fetching controller manager " +
					"pod description",
			)
			cmd = exec.Command("kubectl", "describe",
				"pod", controllerPodName,
				"-n", namespace,
			)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println(
					"Pod description:\n",
					podDescription,
				)
			} else {
				fmt.Println(
					"Failed to describe " +
						"controller pod",
				)
			}
		}
	})

	// Use CI-aware timeouts
	// (defined in e2e_suite_test.go)
	SetDefaultEventuallyTimeout(defaultTimeout)
	SetDefaultEventuallyPollingInterval(
		defaultPollingInterval,
	)

	Context("Manager", func() {
		It("should run successfully", func() {
			utils.TimedBy(
				"validating that the " +
					"controller-manager pod is " +
					"running as expected",
			)
			verifyControllerUp := func(g Gomega) {
				// Get controller-manager pods
				podList, err :=
					utils.GetPodsByLabel(
						ctx, namespace,
						"control-plane",
						"controller-manager",
					)
				g.Expect(err).NotTo(
					HaveOccurred(),
					"Failed to retrieve "+
						"controller-manager pods",
				)

				// Filter pods not being deleted
				var activePods []corev1.Pod
				for i := range podList.Items {
					p := &podList.Items[i]
					if p.DeletionTimestamp == nil {
						activePods = append(
							activePods, *p,
						)
					}
				}
				g.Expect(activePods).To(
					HaveLen(1),
					"expected 1 controller "+
						"pod running",
				)
				controllerPodName =
					activePods[0].Name
				g.Expect(
					controllerPodName,
				).To(ContainSubstring(
					"vault-access-operator",
				))

				// Validate the pod's status
				phase, err :=
					utils.GetPodPhase(
						ctx,
						controllerPodName,
						namespace,
					)
				g.Expect(err).NotTo(
					HaveOccurred(),
				)
				g.Expect(phase).To(
					Equal(corev1.PodRunning),
					"Incorrect controller-"+
						"manager pod status",
				)
			}
			Eventually(verifyControllerUp).Should(
				Succeed(),
			)
		})

		It("should ensure the metrics endpoint "+
			"is serving metrics", func() {
			utils.TimedBy(
				"creating a ClusterRoleBinding " +
					"for the service account to " +
					"allow access to metrics",
			)
			err := utils.CreateObject(ctx,
				&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: metricsRoleBindingName,
					},
					RoleRef: rbacv1.RoleRef{
						APIGroup: "rbac.authorization.k8s.io",
						Kind:     "ClusterRole",
						Name:     "vault-access-operator-metrics-reader",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      serviceAccountName,
							Namespace: namespace,
						},
					},
				},
			)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to create ClusterRoleBinding",
			)

			utils.TimedBy(
				"validating that the metrics " +
					"service is available",
			)
			k8sClient, err := utils.GetK8sClient()
			Expect(err).NotTo(HaveOccurred())

			var svc corev1.Service
			err = k8sClient.Get(ctx,
				client.ObjectKey{
					Name:      metricsServiceName,
					Namespace: namespace,
				},
				&svc,
			)
			Expect(err).NotTo(HaveOccurred(),
				"Metrics service should exist",
			)

			utils.TimedBy(
				"getting the service account token",
			)
			token, err :=
				utils.CreateServiceAccountTokenClientGo(
					ctx, namespace,
					serviceAccountName,
				)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			utils.TimedBy(
				"waiting for the metrics " +
					"endpoint to be ready",
			)
			verifyMetricsEndpointReady :=
				func(g Gomega) {
					var slices discoveryv1.EndpointSliceList
					err := k8sClient.List(ctx,
						&slices,
						client.InNamespace(namespace),
						client.MatchingLabels{
							discoveryv1.LabelServiceName: metricsServiceName,
						},
					)
					g.Expect(err).NotTo(
						HaveOccurred(),
					)
					// Verify at least one slice
					// has ready endpoints on 8443
					hasPort := false
					for i := range slices.Items {
						s := &slices.Items[i]
						hasReady := false
						for _, ep := range s.Endpoints {
							if ep.Conditions.Ready != nil &&
								*ep.Conditions.Ready {
								hasReady = true
								break
							}
						}
						if !hasReady {
							continue
						}
						for _, port := range s.Ports {
							if port.Port != nil &&
								*port.Port == 8443 {
								hasPort = true
							}
						}
					}
					g.Expect(hasPort).To(BeTrue(),
						"Metrics endpoint "+
							"is not ready",
					)
				}
			Eventually(
				verifyMetricsEndpointReady,
			).Should(Succeed())

			utils.TimedBy(
				"verifying that the controller " +
					"manager is serving the " +
					"metrics server",
			)
			verifyMetricsServerStarted :=
				func(g Gomega) {
					cmd := exec.Command(
						"kubectl", "logs",
						controllerPodName,
						"-n", namespace,
					)
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(
						HaveOccurred(),
					)
					g.Expect(output).To(
						ContainSubstring(
							"controller-runtime"+
								".metrics\t"+
								"Serving metrics"+
								" server",
						),
						"Metrics server "+
							"not yet started",
					)
				}
			Eventually(
				verifyMetricsServerStarted,
			).Should(Succeed())

			utils.TimedBy(
				"creating the curl-metrics pod " +
					"to access the metrics endpoint",
			)
			cmd := exec.Command(
				"kubectl", "run", "curl-metrics",
				"--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccount": "%s"
					}
				}`, token,
					metricsServiceName,
					namespace,
					serviceAccountName,
				),
			)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to create curl-metrics pod",
			)

			utils.TimedBy(
				"waiting for the curl-metrics " +
					"pod to complete.",
			)
			verifyCurlUp := func(g Gomega) {
				phase, err :=
					utils.GetPodPhase(
						ctx,
						"curl-metrics",
						namespace,
					)
				g.Expect(err).NotTo(
					HaveOccurred(),
				)
				g.Expect(phase).To(
					Equal(corev1.PodSucceeded),
					"curl pod in wrong status",
				)
			}
			Eventually(verifyCurlUp,
				5*time.Minute,
			).Should(Succeed())

			utils.TimedBy(
				"getting the metrics by " +
					"checking curl-metrics logs",
			)
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_reconcile_total",
			))
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})
})

// getMetricsOutput retrieves and returns the logs from
// the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	utils.TimedBy("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs",
		"curl-metrics", "-n", namespace,
	)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(),
		"Failed to retrieve logs from curl pod",
	)
	Expect(metricsOutput).To(ContainSubstring(
		"< HTTP/1.1 200 OK",
	))
	return metricsOutput
}
