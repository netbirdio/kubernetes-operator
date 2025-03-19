package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
	ctrl "sigs.k8s.io/controller-runtime"
)

var _ = Describe("NBPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		var resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name: resourceName,
		}
		nbpolicy := &netbirdiov1.NBPolicy{}
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
				resource := &netbirdiov1.NBPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:       resourceName,
						Finalizers: []string{"netbird.io/cleanup"},
					},
					Spec: netbirdiov1.NBPolicySpec{
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
			resource := &netbirdiov1.NBPolicy{}
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

			nbresource := &netbirdiov1.NBResource{}
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
					Client:      k8sClient,
					Scheme:      k8sClient.Scheme(),
					netbird:     netbirdClient,
					ClusterName: "Kubernetes",
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

		When("Enough information to create TCP policy", func() {
			It("should create 1 policy", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:      k8sClient,
					Scheme:      k8sClient.Scheme(),
					netbird:     netbirdClient,
					ClusterName: "Kubernetes",
				}

				nbResource := &netbirdiov1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:       "meow",
						Groups:     []string{"test"},
						NetworkID:  "test",
						Address:    "test.default.svc.cluster.local",
						PolicyName: resourceName,
						TCPPorts:   []int32{443},
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				nbResource.Status = netbirdiov1.NBResourceStatus{
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
						Expect(policyReq.Description).To(Or(BeNil(), BeEquivalentTo(util.Ptr(""))))
						Expect(policyReq.Enabled).To(BeTrue())
						Expect(policyReq.SourcePostureChecks).To(BeNil())
						Expect(policyReq.Rules).To(HaveLen(1))
						Expect(policyReq.Rules[0].Action).To(BeEquivalentTo(api.PolicyRuleActionAccept))
						Expect(policyReq.Rules[0].Bidirectional).To(BeTrue())
						Expect(policyReq.Rules[0].Description).To(Or(BeNil(), BeEquivalentTo(util.Ptr(""))))
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
					Client:      k8sClient,
					Scheme:      k8sClient.Scheme(),
					netbird:     netbirdClient,
					ClusterName: "Kubernetes",
				}

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/noexist")
				nbpolicy.Status.TCPPolicyID = util.Ptr("policyid")
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
					Client:      k8sClient,
					Scheme:      k8sClient.Scheme(),
					netbird:     netbirdClient,
					ClusterName: "Kubernetes",
				}

				nbResource := &netbirdiov1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:       "meow",
						Groups:     []string{"test"},
						NetworkID:  "test",
						Address:    "test.default.svc.cluster.local",
						PolicyName: resourceName,
						UDPPorts:   []int32{443},
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				nbResource.Status = netbirdiov1.NBResourceStatus{
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
						Expect(policyReq.Description).To(Or(BeNil(), BeEquivalentTo(util.Ptr(""))))
						Expect(policyReq.Enabled).To(BeTrue())
						Expect(policyReq.SourcePostureChecks).To(BeNil())
						Expect(policyReq.Rules).To(HaveLen(1))
						Expect(policyReq.Rules[0].Action).To(BeEquivalentTo(api.PolicyRuleActionAccept))
						Expect(policyReq.Rules[0].Bidirectional).To(BeTrue())
						Expect(policyReq.Rules[0].Description).To(Or(BeNil(), BeEquivalentTo(util.Ptr(""))))
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
					Client:      k8sClient,
					Scheme:      k8sClient.Scheme(),
					netbird:     netbirdClient,
					ClusterName: "Kubernetes",
				}

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/noexist")
				nbpolicy.Status.UDPPolicyID = util.Ptr("policyid")
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
					Client:      k8sClient,
					Scheme:      k8sClient.Scheme(),
					netbird:     netbirdClient,
					ClusterName: "Kubernetes",
				}

				nbResource := &netbirdiov1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:       "meow",
						Groups:     []string{"test"},
						NetworkID:  "test",
						Address:    "test.default.svc.cluster.local",
						PolicyName: resourceName,
						TCPPorts:   []int32{443},
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				nbResource.Status = netbirdiov1.NBResourceStatus{
					TCPPorts:   []int32{443},
					PolicyName: &resourceName,
					Groups:     []string{"test"},
				}
				Expect(k8sClient.Status().Update(ctx, nbResource)).To(Succeed())

				nbpolicy.Spec.Protocols = []string{"udp"}
				Expect(k8sClient.Update(ctx, nbpolicy)).To(Succeed())

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/test")
				nbpolicy.Status.TCPPolicyID = util.Ptr("policyid")
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
				nbresource := &netbirdiov1.NBResource{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-b"}, nbresource)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())

					By("Cleanup the specific resource instance NBResource")
					Expect(k8sClient.Delete(ctx, nbresource)).To(Succeed())
				}
			})

			It("Should give all information to Update method", func() {
				controllerReconciler := &NBPolicyReconciler{
					Client:      k8sClient,
					Scheme:      k8sClient.Scheme(),
					netbird:     netbirdClient,
					ClusterName: "Kubernetes",
				}

				nbResource := &netbirdiov1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:       "meow",
						Groups:     []string{"test"},
						NetworkID:  "test",
						Address:    "test.default.svc.cluster.local",
						PolicyName: resourceName,
						TCPPorts:   []int32{443},
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				nbResource.Status = netbirdiov1.NBResourceStatus{
					TCPPorts:   []int32{443},
					PolicyName: &resourceName,
					Groups:     []string{"test"},
				}
				Expect(k8sClient.Status().Update(ctx, nbResource)).To(Succeed())

				nbResourceB := &netbirdiov1.NBResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-b",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:       "meow-b",
						Groups:     []string{"test-b"},
						NetworkID:  "test",
						Address:    "test-b.default.svc.cluster.local",
						PolicyName: resourceName,
						TCPPorts:   []int32{80},
					},
				}
				Expect(k8sClient.Create(ctx, nbResourceB)).To(Succeed())

				nbResourceB.Status = netbirdiov1.NBResourceStatus{
					TCPPorts:   []int32{80},
					PolicyName: &resourceName,
					Groups:     []string{"test-b"},
				}
				Expect(k8sClient.Status().Update(ctx, nbResourceB)).To(Succeed())

				nbpolicy.Status.ManagedServiceList = append(nbpolicy.Status.ManagedServiceList, "default/test", "default/test-b")
				nbpolicy.Status.TCPPolicyID = util.Ptr("policyid")
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
						Expect(policyReq.Description).To(Or(BeNil(), BeEquivalentTo(util.Ptr(""))))
						Expect(policyReq.Enabled).To(BeTrue())
						Expect(policyReq.SourcePostureChecks).To(BeNil())
						Expect(policyReq.Rules).To(HaveLen(1))
						Expect(policyReq.Rules[0].Action).To(BeEquivalentTo(api.PolicyRuleActionAccept))
						Expect(policyReq.Rules[0].Bidirectional).To(BeTrue())
						Expect(policyReq.Rules[0].Description).To(Or(BeNil(), BeEquivalentTo(util.Ptr(""))))
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
					Client:      k8sClient,
					Scheme:      k8sClient.Scheme(),
					netbird:     netbirdClient,
					ClusterName: "Kubernetes",
				}

				nbpolicy.Status.TCPPolicyID = util.Ptr("policyidtcp")
				nbpolicy.Status.UDPPolicyID = util.Ptr("policyidudp")
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
