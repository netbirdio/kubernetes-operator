// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

var _ = Describe("NBPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		var resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name: resourceName,
		}
		nbpolicy := &nbv1.NBPolicy{}
		var netbirdClient *netbird.Client
		var mux *http.ServeMux
		var server *httptest.Server

		BeforeEach(func() {
			ctrl.SetLogger(logr.New(GinkgoLogr.GetSink()))
			mux = &http.ServeMux{}
			server = httptest.NewServer(mux)
			netbirdClient = netbird.New(server.URL, "ABC")

			By("creating the custom resource for the Kind NBPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, nbpolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &nbv1.NBPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:       resourceName,
						Finalizers: []string{"netbird.io/cleanup"},
					},
					Spec: nbv1.NBPolicySpec{
						Name:          "Test",
						SourceGroups:  []string{"All"},
						Bidirectional: true,
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
				nbpolicy = resource
			}
		})

		AfterEach(func() {
			resource := &nbv1.NBPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())

				if len(resource.Finalizers) > 0 {
					resource.Finalizers = nil
					Expect(k8sClient.Update(ctx, resource)).To(Succeed())
				}

				By("Cleanup the specific resource instance NBPolicy")
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}

			nbresource := &nbv1.NBResource{}
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test"}, nbresource)
			if !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())

				By("Cleanup the specific resource instance NBResource")
				Expect(k8sClient.Delete(ctx, nbresource)).To(Succeed())
			}
		})
		When("Not enough information to create policy", func() {
			It("should not create any policy", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "meow",
							Name: "All",
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		When("Nothing changed since the last reconcile", func() {
			It("should keep the status and its condition timestamps", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					bs, err := json.Marshal([]api.Group{{Id: "meow", Name: "All"}})
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				Expect(err).NotTo(HaveOccurred())
				Expect(k8sClient.Get(ctx, typeNamespacedName, nbpolicy)).To(Succeed())
				Expect(nbpolicy.Status.Conditions).To(HaveLen(1))
				Expect(nbpolicy.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
				resourceVersion := nbpolicy.ResourceVersion
				first := nbpolicy.Status.Conditions[0]

				// Condition times have second precision, so a rewrite only changes the
				// object, and triggers the next reconcile, once a second has passed.
				time.Sleep(1100 * time.Millisecond)

				_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				Expect(err).NotTo(HaveOccurred())
				Expect(k8sClient.Get(ctx, typeNamespacedName, nbpolicy)).To(Succeed())
				Expect(nbpolicy.ResourceVersion).To(Equal(resourceVersion), "unchanged status should not be written")
				Expect(nbpolicy.Status.Conditions[0].LastProbeTime).To(Equal(first.LastProbeTime), "probe time should not be restamped")
				Expect(nbpolicy.Status.Conditions[0].LastTransitionTime).To(Equal(first.LastTransitionTime), "transition time should not be restamped")

				By("writing the status again once the condition changes")
				nbpolicy.Status.Conditions = nbv1.NBConditionFalse("APIError", "boom")
				Expect(k8sClient.Status().Update(ctx, nbpolicy)).To(Succeed())

				_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				Expect(err).NotTo(HaveOccurred())
				Expect(k8sClient.Get(ctx, typeNamespacedName, nbpolicy)).To(Succeed())
				Expect(nbpolicy.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
				Expect(nbpolicy.Status.Conditions[0].LastTransitionTime.After(first.LastTransitionTime.Time)).To(BeTrue(), "transition time should be restamped")
			})
		})

		When("Enough information to create TCP policy", func() {
			It("should create 1 policy", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				nbResource := &nbv1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: nbv1.NBResourceSpec{
						Name:       "meow",
						Groups:     []string{"test"},
						NetworkID:  "test",
						Address:    "test.default.svc.cluster.local",
						PolicyName: resourceName,
						TCPPorts:   []int32{443},
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				nbResource.Status = nbv1.NBResourceStatus{
					TCPPorts:   []int32{443},
					PolicyName: &resourceName,
					Groups:     []string{"test"},
				}
				Expect(k8sClient.Status().Update(ctx, nbResource)).To(Succeed())

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/test")
				Expect(k8sClient.Status().Update(ctx, nbpolicy)).To(Succeed())

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "meow",
							Name: "All",
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				policyCreated := false
				mux.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					if r.Method == http.MethodPost {
						var policyReq api.PostApiPoliciesJSONRequestBody
						bs, err := io.ReadAll(r.Body)
						Expect(err).NotTo(HaveOccurred())
						err = json.Unmarshal(bs, &policyReq)
						Expect(err).NotTo(HaveOccurred())
						Expect(policyReq.Name).To(Equal("Test TCP"))
						Expect(policyReq.Description).To(Or(BeNil(), BeEquivalentTo(new(""))))
						Expect(policyReq.Enabled).To(BeTrue())
						Expect(policyReq.SourcePostureChecks).To(BeNil())
						Expect(policyReq.Rules).To(HaveLen(1))
						Expect(policyReq.Rules[0].Action).To(BeEquivalentTo(api.PolicyRuleActionAccept))
						Expect(policyReq.Rules[0].Bidirectional).To(BeTrue())
						Expect(policyReq.Rules[0].Description).To(Or(BeNil(), BeEquivalentTo(new(""))))
						Expect(policyReq.Rules[0].DestinationResource).To(BeNil())
						Expect(policyReq.Rules[0].Destinations).NotTo(BeNil())
						Expect(*policyReq.Rules[0].Destinations).To(HaveLen(1))
						Expect((*policyReq.Rules[0].Destinations)[0]).To(Equal("test"))
						Expect(policyReq.Rules[0].Enabled).To(BeTrue())
						Expect(policyReq.Rules[0].Name).To(Equal("Test TCP"))
						Expect(policyReq.Rules[0].Ports).NotTo(BeNil())
						Expect((*policyReq.Rules[0].Ports)).To(HaveLen(1))
						Expect((*policyReq.Rules[0].Ports)[0]).To(Equal("443"))
						Expect(policyReq.Rules[0].Protocol).To(BeEquivalentTo(api.PolicyRuleProtocolTcp))
						Expect(policyReq.Rules[0].SourceResource).To(BeNil())
						Expect(policyReq.Rules[0].Sources).NotTo(BeNil())
						Expect(*policyReq.Rules[0].Sources).To(HaveLen(1))
						Expect((*policyReq.Rules[0].Sources)[0]).To(Equal("meow"))

						policyCreated = true
						resp := api.Policy{
							Id: &resourceName,
						}
						bs, err = json.Marshal(resp)
						Expect(err).NotTo(HaveOccurred())
						_, err = w.Write(bs)
						Expect(err).NotTo(HaveOccurred())
					}
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(policyCreated).To(BeTrue())
			})
		})

		When("TCP information no longer sufficient", func() {
			It("should delete tcp policy", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/noexist")
				nbpolicy.Status.TCPPolicyID = new("policyid")
				Expect(k8sClient.Status().Update(ctx, nbpolicy)).To(Succeed())

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "meow",
							Name: "All",
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				policyDeleted := false
				mux.HandleFunc("/api/policies/policyid", func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodDelete {
						policyDeleted = true
						_, err := w.Write([]byte("{}"))
						Expect(err).NotTo(HaveOccurred())
					}
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(policyDeleted).To(BeTrue())
			})
		})

		When("Enough information to create UDP policy", func() {
			It("should create 1 policy", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				nbResource := &nbv1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: nbv1.NBResourceSpec{
						Name:       "meow",
						Groups:     []string{"test"},
						NetworkID:  "test",
						Address:    "test.default.svc.cluster.local",
						PolicyName: resourceName,
						UDPPorts:   []int32{443},
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				nbResource.Status = nbv1.NBResourceStatus{
					UDPPorts:   []int32{443},
					PolicyName: &resourceName,
					Groups:     []string{"test"},
				}
				Expect(k8sClient.Status().Update(ctx, nbResource)).To(Succeed())

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/test")
				Expect(k8sClient.Status().Update(ctx, nbpolicy)).To(Succeed())

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "meow",
							Name: "All",
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				policyCreated := false
				mux.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					if r.Method == http.MethodPost {
						var policyReq api.PostApiPoliciesJSONRequestBody
						bs, err := io.ReadAll(r.Body)
						Expect(err).NotTo(HaveOccurred())
						err = json.Unmarshal(bs, &policyReq)
						Expect(err).NotTo(HaveOccurred())
						Expect(policyReq.Name).To(Equal("Test UDP"))
						Expect(policyReq.Description).To(Or(BeNil(), BeEquivalentTo(new(""))))
						Expect(policyReq.Enabled).To(BeTrue())
						Expect(policyReq.SourcePostureChecks).To(BeNil())
						Expect(policyReq.Rules).To(HaveLen(1))
						Expect(policyReq.Rules[0].Action).To(BeEquivalentTo(api.PolicyRuleActionAccept))
						Expect(policyReq.Rules[0].Bidirectional).To(BeTrue())
						Expect(policyReq.Rules[0].Description).To(Or(BeNil(), BeEquivalentTo(new(""))))
						Expect(policyReq.Rules[0].DestinationResource).To(BeNil())
						Expect(policyReq.Rules[0].Destinations).NotTo(BeNil())
						Expect(*policyReq.Rules[0].Destinations).To(HaveLen(1))
						Expect((*policyReq.Rules[0].Destinations)[0]).To(Equal("test"))
						Expect(policyReq.Rules[0].Enabled).To(BeTrue())
						Expect(policyReq.Rules[0].Name).To(Equal("Test UDP"))
						Expect(policyReq.Rules[0].Ports).NotTo(BeNil())
						Expect((*policyReq.Rules[0].Ports)).To(HaveLen(1))
						Expect((*policyReq.Rules[0].Ports)[0]).To(Equal("443"))
						Expect(policyReq.Rules[0].Protocol).To(BeEquivalentTo(api.PolicyRuleProtocolUdp))
						Expect(policyReq.Rules[0].SourceResource).To(BeNil())
						Expect(policyReq.Rules[0].Sources).NotTo(BeNil())
						Expect(*policyReq.Rules[0].Sources).To(HaveLen(1))
						Expect((*policyReq.Rules[0].Sources)[0]).To(Equal("meow"))

						policyCreated = true
						resp := api.Policy{
							Id: &resourceName,
						}
						bs, err = json.Marshal(resp)
						Expect(err).NotTo(HaveOccurred())
						_, err = w.Write(bs)
						Expect(err).NotTo(HaveOccurred())
					}
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(policyCreated).To(BeTrue())
			})
		})

		When("UDP information no longer sufficient", func() {
			It("should delete udp policy", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/noexist")
				nbpolicy.Status.UDPPolicyID = new("policyid")
				Expect(k8sClient.Status().Update(ctx, nbpolicy)).To(Succeed())

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "meow",
							Name: "All",
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				policyDeleted := false
				mux.HandleFunc("/api/policies/policyid", func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodDelete {
						policyDeleted = true
						_, err := w.Write([]byte("{}"))
						Expect(err).NotTo(HaveOccurred())
					}
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(policyDeleted).To(BeTrue())
			})
		})

		When("Existing protocol gets restricted", func() {
			It("Should delete protocol policy", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				nbResource := &nbv1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: nbv1.NBResourceSpec{
						Name:       "meow",
						Groups:     []string{"test"},
						NetworkID:  "test",
						Address:    "test.default.svc.cluster.local",
						PolicyName: resourceName,
						TCPPorts:   []int32{443},
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				nbResource.Status = nbv1.NBResourceStatus{
					TCPPorts:   []int32{443},
					PolicyName: &resourceName,
					Groups:     []string{"test"},
				}
				Expect(k8sClient.Status().Update(ctx, nbResource)).To(Succeed())

				nbpolicy.Spec.Protocols = []string{"udp"}
				Expect(k8sClient.Update(ctx, nbpolicy)).To(Succeed())

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/test")
				nbpolicy.Status.TCPPolicyID = new("policyid")
				Expect(k8sClient.Status().Update(ctx, nbpolicy)).To(Succeed())

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "meow",
							Name: "All",
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				policyDeleted := false
				mux.HandleFunc("/api/policies/policyid", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					if r.Method == http.MethodDelete {
						policyDeleted = true
						_, err := w.Write([]byte("{}"))
						Expect(err).NotTo(HaveOccurred())
					}
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(policyDeleted).To(BeTrue())
			})
		})

		When("Updating existing policy", func() {
			AfterEach(func() {
				nbresource := &nbv1.NBResource{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-b"}, nbresource)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())

					By("Cleanup the specific resource instance NBResource")
					Expect(k8sClient.Delete(ctx, nbresource)).To(Succeed())
				}
			})

			It("Should give all information to Update method", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				nbResource := &nbv1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: nbv1.NBResourceSpec{
						Name:       "meow",
						Groups:     []string{"test"},
						NetworkID:  "test",
						Address:    "test.default.svc.cluster.local",
						PolicyName: resourceName,
						TCPPorts:   []int32{443},
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				nbResource.Status = nbv1.NBResourceStatus{
					TCPPorts:   []int32{443},
					PolicyName: &resourceName,
					Groups:     []string{"test"},
				}
				Expect(k8sClient.Status().Update(ctx, nbResource)).To(Succeed())

				nbResourceB := &nbv1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-b",
						Namespace: "default",
					},
					Spec: nbv1.NBResourceSpec{
						Name:       "meow-b",
						Groups:     []string{"test-b"},
						NetworkID:  "test",
						Address:    "test-b.default.svc.cluster.local",
						PolicyName: resourceName,
						TCPPorts:   []int32{80},
					},
				}
				Expect(k8sClient.Create(ctx, nbResourceB)).To(Succeed())

				nbResourceB.Status = nbv1.NBResourceStatus{
					TCPPorts:   []int32{80},
					PolicyName: &resourceName,
					Groups:     []string{"test-b"},
				}
				Expect(k8sClient.Status().Update(ctx, nbResourceB)).To(Succeed())

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/test", "default/test-b")
				nbpolicy.Status.TCPPolicyID = new("policyid")
				Expect(k8sClient.Status().Update(ctx, nbpolicy)).To(Succeed())

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "meow",
							Name: "All",
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				policyUpdated := false
				mux.HandleFunc("/api/policies/policyid", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					if r.Method == http.MethodPut {
						policyUpdated = true

						var policyReq api.PostApiPoliciesJSONRequestBody
						bs, err := io.ReadAll(r.Body)
						Expect(err).NotTo(HaveOccurred())
						err = json.Unmarshal(bs, &policyReq)
						Expect(err).NotTo(HaveOccurred())
						Expect(policyReq.Name).To(Equal("Test TCP"))
						Expect(policyReq.Description).To(Or(BeNil(), BeEquivalentTo(new(""))))
						Expect(policyReq.Enabled).To(BeTrue())
						Expect(policyReq.SourcePostureChecks).To(BeNil())
						Expect(policyReq.Rules).To(HaveLen(1))
						Expect(policyReq.Rules[0].Action).To(BeEquivalentTo(api.PolicyRuleActionAccept))
						Expect(policyReq.Rules[0].Bidirectional).To(BeTrue())
						Expect(policyReq.Rules[0].Description).To(Or(BeNil(), BeEquivalentTo(new(""))))
						Expect(policyReq.Rules[0].DestinationResource).To(BeNil())
						Expect(policyReq.Rules[0].Destinations).NotTo(BeNil())
						Expect(*policyReq.Rules[0].Destinations).To(HaveLen(2))
						Expect((*policyReq.Rules[0].Destinations)).To(ConsistOf([]string{"test", "test-b"}))
						Expect(policyReq.Rules[0].Enabled).To(BeTrue())
						Expect(policyReq.Rules[0].Name).To(Equal("Test TCP"))
						Expect(policyReq.Rules[0].Ports).NotTo(BeNil())
						Expect((*policyReq.Rules[0].Ports)).To(HaveLen(2))
						Expect((*policyReq.Rules[0].Ports)).To(ConsistOf([]string{"443", "80"}))
						Expect(policyReq.Rules[0].Protocol).To(BeEquivalentTo(api.PolicyRuleProtocolTcp))
						Expect(policyReq.Rules[0].SourceResource).To(BeNil())
						Expect(policyReq.Rules[0].Sources).NotTo(BeNil())
						Expect(*policyReq.Rules[0].Sources).To(HaveLen(1))
						Expect((*policyReq.Rules[0].Sources)[0]).To(Equal("meow"))

						_, err = w.Write([]byte("{}"))
						Expect(err).NotTo(HaveOccurred())
					}
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(policyUpdated).To(BeTrue())
			})
		})

		When("NBPolicy is set for deletion", func() {
			It("should delete Policies", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				nbpolicy.Status.TCPPolicyID = new("policyidtcp")
				nbpolicy.Status.UDPPolicyID = new("policyidudp")
				Expect(k8sClient.Status().Update(ctx, nbpolicy)).To(Succeed())

				Expect(k8sClient.Delete(ctx, nbpolicy)).To(Succeed())

				tcpPolicyDeleted := false
				mux.HandleFunc("/api/policies/policyidtcp", func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodDelete {
						tcpPolicyDeleted = true
						_, err := w.Write([]byte("{}"))
						Expect(err).NotTo(HaveOccurred())
					}
				})

				udpPolicyDeleted := false
				mux.HandleFunc("/api/policies/policyidudp", func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodDelete {
						udpPolicyDeleted = true
						_, err := w.Write([]byte("{}"))
						Expect(err).NotTo(HaveOccurred())
					}
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(tcpPolicyDeleted).To(BeTrue())
				Expect(udpPolicyDeleted).To(BeTrue())

				err = k8sClient.Get(ctx, typeNamespacedName, nbpolicy)
				Expect(errors.IsNotFound(err)).To(BeTrue())
			})
		})
	})
})

var _ = Describe("NBPolicy Controller under a manager", func() {
	It("stops reconciling an unchanged policy when the management API is slow", func() {
		var mx sync.Mutex
		puts := 0
		putCount := func() int {
			mx.Lock()
			defer mx.Unlock()
			return puts
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]api.Group{{Id: "g-all", Name: "All"}})
		})
		policy := api.Policy{Id: new("pol-1"), Name: "Slow TCP", Enabled: true}
		mux.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(policy)
		})
		mux.HandleFunc("/api/policies/pol-1", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				mx.Lock()
				puts++
				mx.Unlock()
			}
			_ = json.NewEncoder(w).Encode(policy)
		})
		// About 1.2s per reconcile, so every status write lands in a new second and
		// changes the object, which is what kept the controller looping.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(400 * time.Millisecond)
			mux.ServeHTTP(w, r)
		}))
		DeferCleanup(srv.Close)

		ctx := context.Background()
		suffix := rand.String(5)
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "nbpolicy-" + suffix}}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, ns)
		policyName := "slow-api-" + suffix

		nbResource := &nbv1.NBResource{
			ObjectMeta: metav1.ObjectMeta{Name: "res", Namespace: ns.Name},
			Spec: nbv1.NBResourceSpec{
				Name:      "res",
				NetworkID: "net-1",
				Address:   "10.0.0.1",
				Groups:    []string{"dest"},
				TCPPorts:  []int32{80},
			},
		}
		Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, nbResource)
		nbResource.Status.PolicyName = &policyName
		nbResource.Status.Groups = []string{"g-dest"}
		nbResource.Status.PolicyNameMapping = map[string]string{}
		Expect(k8sClient.Status().Update(ctx, nbResource)).To(Succeed())

		nbPolicy := &nbv1.NBPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policyName},
			Spec: nbv1.NBPolicySpec{
				Name:          "Slow",
				SourceGroups:  []string{"All"},
				Bidirectional: true,
			},
		}
		Expect(k8sClient.Create(ctx, nbPolicy)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, nbPolicy)
		nbPolicy.Status.ManagedServiceList = []string{ns.Name + "/res"}
		Expect(k8sClient.Status().Update(ctx, nbPolicy)).To(Succeed())

		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:                 scheme.Scheme,
			Metrics:                metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
			Controller:             config.Controller{SkipNameValidation: new(true)},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect((&NBPolicyReconciler{Client: mgr.GetClient(), Netbird: netbird.New(srv.URL, "ABC")}).SetupWithManager(mgr)).To(Succeed())

		mgrCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			Expect(mgr.Start(mgrCtx)).To(Succeed())
		}()
		DeferCleanup(func() {
			cancel()
			<-done
		})

		key := types.NamespacedName{Name: policyName}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, key, nbPolicy)).To(Succeed())
			g.Expect(nbPolicy.Status.TCPPolicyID).To(HaveValue(Equal("pol-1")))
		}, 10*time.Second, 100*time.Millisecond).Should(Succeed())

		// Let the reconcile triggered by that status write finish.
		time.Sleep(2500 * time.Millisecond)
		putsBefore := putCount()
		Expect(k8sClient.Get(ctx, key, nbPolicy)).To(Succeed())
		probeBefore := nbPolicy.Status.Conditions[0].LastProbeTime

		time.Sleep(3 * time.Second)
		Expect(putCount()).To(Equal(putsBefore), "unchanged policy should not be updated again")
		Expect(k8sClient.Get(ctx, key, nbPolicy)).To(Succeed())
		Expect(nbPolicy.Status.Conditions[0].LastProbeTime).To(Equal(probeBefore), "unchanged condition should not be restamped")
		Expect(putsBefore).To(BeNumerically("<=", 2), "controller should settle after the policy is created")
	})
})
