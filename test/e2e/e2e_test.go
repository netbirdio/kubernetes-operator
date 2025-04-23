/*
Copyright 2025.

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
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/netbirdio/kubernetes-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "netbird"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "kubernetes-operator-metrics"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string
	var netbirdClient *netbird.Client

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("deploying the kubernetes-operator")
		out, err := utils.Run(exec.Command("kubectl", "get", "node", "-o", "json"))
		Expect(err).NotTo(HaveOccurred(), "Failed to get nodes")
		nodesGetOutput := make(map[string]any)
		err = json.Unmarshal([]byte(out), &nodesGetOutput)
		Expect(err).NotTo(HaveOccurred(), "Failed to get nodes")
		nodeIPs := (nodesGetOutput["items"].([]any))[0].(map[string]any)["status"].(map[string]any)["addresses"].([]any)
		managementIP := ""
		for _, v := range nodeIPs {
			addrType := v.(map[string]any)["type"]
			if addrType == "InternalIP" {
				managementIP = v.(map[string]any)["address"].(string)
				break
			}
		}

		Expect(managementIP).NotTo(BeEmpty())
		managementIPParts := strings.Split(managementIP, ".")
		managementIP = fmt.Sprintf("http://%s.%s.0.1:8080", managementIPParts[0], managementIPParts[1])
		cmd = exec.Command(
			"make",
			"deploy-e2e",
			fmt.Sprintf("IMG=%s", projectImage),
			fmt.Sprintf("MGMT_HOST=%s", managementIP),
		)
		out, err = utils.Run(cmd)
		if err != nil {
			fmt.Println(out)
		}
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the kubernetes-operator")

		netbirdClient = netbird.New("http://127.0.0.1:8080", apiToken)
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the kubernetes-operator")
		cmd = exec.Command("make", "undeploy-e2e")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the kubernetes-operator pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the kubernetes-operator pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "app.kubernetes.io/component=operator,app.kubernetes.io/name=kubernetes-operator",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve kubernetes-operator pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("kubernetes-operator"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect kubernetes-operator pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("validating that the metrics service is available")
			cmd := exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8080"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v http://%s.%s.svc.cluster.local:8080/metrics"],
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
						}]
					}
				}`, metricsServiceName, namespace))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_reconcile_total",
			))
		})

		It("should provisioned cert-manager", func() {
			By("validating that cert-manager has the certificate Secret")
			verifyCertManager := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secrets", "kubernetes-operator-tls", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyCertManager).Should(Succeed())
		})

		It("should have CA injection for mutating webhooks", func() {
			By("checking CA injection for mutating webhooks")
			verifyCAInjection := func(g Gomega) {
				cmd := exec.Command("kubectl", "get",
					"mutatingwebhookconfigurations.admissionregistration.k8s.io",
					"kubernetes-operator-mpod-webhook",
					"-o", "go-template={{ range .webhooks }}{{ .clientConfig.caBundle }}{{ end }}")
				mwhOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(len(mwhOutput)).To(BeNumerically(">", 10))
			}
			Eventually(verifyCAInjection).Should(Succeed())
		})

		It("should have CA injection for validating webhooks", func() {
			By("checking CA injection for validating webhooks")
			verifyCAInjection := func(g Gomega) {
				cmd := exec.Command("kubectl", "get",
					"validatingwebhookconfigurations.admissionregistration.k8s.io",
					"kubernetes-operator-vnbsetupkey-webhook",
					"-o", "go-template={{ range .webhooks }}{{ .clientConfig.caBundle }}{{ end }}")
				vwhOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(len(vwhOutput)).To(BeNumerically(">", 10))
			}
			Eventually(verifyCAInjection).Should(Succeed())
		})

		Context("NBSetupKey", Ordered, func() {
			Describe("Basic functionality", Ordered, func() {
				BeforeAll(func() {
					cmd := exec.Command(
						"kubectl", "create", "secret", "generic",
						"--from-literal", "sk=EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE",
						"-n", "default",
						"netbird-sk",
					)
					_, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
				})

				AfterAll(func() {
					cmd := exec.Command("kubectl", "delete", "--ignore-not-found", "secret", "netbird-sk")
					_, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
					cmd = exec.Command("kubectl", "delete", "--ignore-not-found", "NBSetupKey", "main")
					_, err = utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should allow setupkey resource to be created", func() {
					cmd := exec.Command("kubectl", "apply", "-f", "-")
					cmd.Stdin = strings.NewReader(`{
							"apiVersion": "netbird.io/v1",
							"kind": "NBSetupKey",
							"metadata": {
								"name": "main"
							},
							"spec": {
								"managementURL": "https://netbird.example.com",
								"secretKeyRef": {
									"name": "netbird-sk",
									"key": "sk"
								}
							}
						}`)

					_, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should set status.conditions[0].status to True", func() {
					verifyNBSetupKeyStatus := func(g Gomega) {
						cmd := exec.Command(
							"kubectl", "get",
							"nbsetupkeys", "main",
							"-o", "jsonpath={.status.conditions[0].status}",
						)
						vnbskOutput, err := utils.Run(cmd)
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(vnbskOutput).To(ContainSubstring("True"))
					}
					Eventually(verifyNBSetupKeyStatus).Should(Succeed())
				})

				It("should inject netbird container into a new pod with annotation", func() {
					cmd := exec.Command(
						"kubectl", "run", "test-pod-inject",
						"--dry-run=server", "--image=busybox",
						"--annotations", "netbird.io/setup-key=main",
						"-n", "default",
						"-o", "jsonpath={.spec.containers[1].name}",
					)
					out, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
					Expect(out).To(ContainSubstring("netbird"))
				})

				It("should not inject netbird container into a new pod without annotation", func() {
					cmd := exec.Command(
						"kubectl", "run", "test-pod-inject",
						"--dry-run=server", "--image=busybox",
						"-n", "default",
						"-o", "jsonpath={.spec.containers}",
					)
					out, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
					Expect(out).NotTo(ContainSubstring("netbird"))
				})

				It("should fail new pod with incorrect annotation", func() {
					cmd := exec.Command(
						"kubectl", "run", "test-pod-inject",
						"--dry-run=server", "--image=busybox",
						"--annotations", "netbird.io/setup-key=nothing",
						"-n", "default",
						"-o", "jsonpath={.spec.containers}",
					)
					out, err := utils.Run(cmd)
					Expect(err).To(HaveOccurred())
					Expect(out).To(ContainSubstring("admission"))
				})
			})
			Describe("Post-create validation", Ordered, func() {
				BeforeAll(func() {
					cmd := exec.Command(
						"kubectl", "create", "secret", "generic",
						"--from-literal", "sk=EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE",
						"-n", "default",
						"netbird-sk",
					)
					_, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())

					cmd = exec.Command("kubectl", "apply", "-f", "-")
					cmd.Stdin = strings.NewReader(`{
							"apiVersion": "netbird.io/v1",
							"kind": "NBSetupKey",
							"metadata": {
								"name": "main"
							},
							"spec": {
								"managementURL": "https://netbird.example.com",
								"secretKeyRef": {
									"name": "netbird-sk",
									"key": "sk"
								}
							}
						}`)

					_, err = utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
				})

				AfterAll(func() {
					cmd := exec.Command("kubectl", "delete", "--ignore-not-found", "secret", "netbird-sk")
					_, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
					cmd = exec.Command("kubectl", "delete", "--ignore-not-found", "NBSetupKey", "main")
					_, err = utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should set status.conditions[0].status to True", func() {
					verifyNBSetupKeyStatus := func(g Gomega) {
						cmd := exec.Command(
							"kubectl", "get",
							"nbsetupkeys", "main",
							"-o", "jsonpath={.status.conditions[0].status}",
						)
						vnbskOutput, err := utils.Run(cmd)
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(vnbskOutput).To(ContainSubstring("True"))
					}
					Eventually(verifyNBSetupKeyStatus).Should(Succeed())
				})

				It("should update status after secret is updated", func() {
					cmd := exec.Command(
						"kubectl", "apply", "-f", "-",
					)
					cmd.Stdin = strings.NewReader(`{
							"kind": "Secret",
							"apiVersion": "v1",
							"metadata": {
									"name": "netbird-sk"
							},
							"stringData": {
									"sk": "WewWewInvalidWewWew"
							}
					}`)
					_, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should update status.conditions[0].status to False", func() {
					verifyNBSetupKeyStatus := func(g Gomega) {
						cmd := exec.Command(
							"kubectl", "get",
							"nbsetupkeys", "main",
							"-o", "jsonpath={.status.conditions[0].status}",
						)
						vnbskOutput, err := utils.Run(cmd)
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(vnbskOutput).To(ContainSubstring("False"))
					}
					Eventually(verifyNBSetupKeyStatus).Should(Succeed())
				})
			})
		})

		Context("Ingress", Ordered, func() {
			BeforeAll(func() {
				_, err := utils.Run(exec.Command("kubectl", "create", "deployment", "--image=nginx", "exposable"))
				Expect(err).NotTo(HaveOccurred())
				_, err = utils.Run(exec.Command("kubectl", "expose", "deployment", "--port=80", "exposable"))
				Expect(err).NotTo(HaveOccurred())
			})

			AfterAll(func() {
				_, err := utils.Run(exec.Command("kubectl", "delete", "deployment", "--ignore-not-found", "exposable"))
				Expect(err).NotTo(HaveOccurred())
				_, err = utils.Run(exec.Command("kubectl", "delete", "service", "--ignore-not-found", "exposable"))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should create Network", func() {
				Eventually(func(g Gomega) {
					networks, err := netbirdClient.Networks.List(context.Background())
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(networks).To(HaveLen(1))
				}).Should(Succeed())
			})

			networkID := func() string {
				defer GinkgoHelper()
				networks, err := netbirdClient.Networks.List(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(networks).To(HaveLen(1))
				return networks[0].Id
			}

			It("should create NetworkRouter", func() {
				Eventually(func(g Gomega) {
					routers, err := netbirdClient.Networks.Routers(networkID()).List(context.Background())
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(routers).To(HaveLen(1))
				}).Should(Succeed())
			})

			It("should create router deployment", func() {
				Eventually(func(g Gomega) {
					_, err := utils.Run(exec.Command("kubectl", "get", "deployment", "router", "-n", "netbird"))
					Expect(err).NotTo(HaveOccurred())
				}).Should(Succeed())
			})

			groupsToNames := func(i []api.Group) []string {
				ret := make([]string, len(i))
				for j, k := range i {
					ret[j] = k.Name
				}
				return ret
			}

			It("should create router group", func() {
				Eventually(func(g Gomega) {
					groups, err := netbirdClient.Groups.List(context.Background())
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(groups).To(WithTransform(groupsToNames, ContainElement("kubernetes")))
				}).Should(Succeed())
			})

			It("should not expose service by default", func() {
				_, err := utils.Run(exec.Command("kubectl", "get", "NBResource", "exposable"))
				Expect(err).To(HaveOccurred())
			})

			When("Service is annotated with expose", Ordered, func() {
				BeforeAll(func() {
					_, err := utils.Run(exec.Command("kubectl", "annotate", "service", "exposable", "netbird.io/expose=true"))
					Expect(err).NotTo(HaveOccurred())
				})

				It("should create NBResource", func() {
					Eventually(func(g Gomega) {
						_, err := utils.Run(exec.Command("kubectl", "get", "NBResource", "exposable"))
						g.Expect(err).NotTo(HaveOccurred())
					}).Should(Succeed())
				})

				It("should create Network Resource", func() {
					Eventually(func(g Gomega) {
						resources, err := netbirdClient.Networks.Resources(networkID()).List(context.Background())
						Expect(err).NotTo(HaveOccurred())
						resourcesToNames := func(r []api.NetworkResource) []string {
							ret := make([]string, len(r))
							for i, j := range r {
								ret[i] = j.Name
							}
							return ret
						}
						Expect(resources).To(WithTransform(resourcesToNames, ContainElement("default-exposable")))
					}).Should(Succeed())
				})

				It("should create Group", func() {
					Eventually(func(g Gomega) {
						groups, err := netbirdClient.Groups.List(context.Background())
						Expect(err).NotTo(HaveOccurred())
						Expect(groups).To(WithTransform(groupsToNames, ContainElement("kubernetes-default-exposable")))
					}).Should(Succeed())
				})
			})

			When("Service is annotated with policy", Ordered, func() {
				BeforeAll(func() {
					_, err := utils.Run(exec.Command("kubectl", "annotate", "service", "exposable", "netbird.io/policy=default"))
					Expect(err).NotTo(HaveOccurred())
				})

				It("should add service to policy status", func() {
					Eventually(func(g Gomega) {
						out, err := utils.Run(exec.Command(
							"kubectl", "get", "NBPolicy", "default", "-o", "jsonpath={.status.managedServiceList}",
						))
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(out).To(ContainSubstring("default/exposable"))
					}).Should(Succeed())
				})

				It("should create policy on NetBird", func() {
					Eventually(func(g Gomega) {
						out, err := utils.Run(exec.Command(
							"kubectl", "get", "NBPolicy", "default", "-o", "jsonpath={.status.tcpPolicyID}",
						))
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(out).NotTo(BeEmpty())
					}).Should(Succeed())

					Eventually(func(g Gomega) {
						policies, err := netbirdClient.Policies.List(context.Background())
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(policies).To(HaveLen(1))
						g.Expect(policies[0].Name).To(ContainSubstring("Kubernetes Default Group"))
					}).Should(Succeed())
				})
			})

			When("Service is annotated with a non-existent policy", Ordered, func() {
				BeforeAll(func() {
					_, err := utils.Run(exec.Command(
						"kubectl", "annotate", "service", "exposable", "--overwrite",
						"netbird.io/policy=custom", "netbird.io/policy-source-groups=All", "netbird.io/policy-name=custom:E2E",
					))
					Expect(err).NotTo(HaveOccurred())
				})

				It("should create NBPolicy", func() {
					Eventually(func(g Gomega) {
						out, err := utils.Run(exec.Command(
							"kubectl", "get", "NBPolicy", "custom-default-exposable", "-o", "jsonpath={.status.managedServiceList}",
						))
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(out).To(ContainSubstring("default/exposable"))
					}).Should(Succeed())
				})

				It("should create policy on NetBird", func() {
					Eventually(func(g Gomega) {
						out, err := utils.Run(exec.Command(
							"kubectl", "get", "NBPolicy", "custom-default-exposable", "-o", "jsonpath={.status.tcpPolicyID}",
						))
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(out).NotTo(BeEmpty())
					}).Should(Succeed())

					Eventually(func(g Gomega) {
						policies, err := netbirdClient.Policies.List(context.Background())
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(policies).To(HaveLen(1))
						g.Expect(policies[0].Name).To(ContainSubstring("E2E"))
					}).Should(Succeed())
				})
			})
		})
	})
})

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}
