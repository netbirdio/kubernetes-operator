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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
)

var _ = Describe("NBRoutingPeer Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		nbroutingpeer := &netbirdiov1.NBRoutingPeer{}
		var netbirdClient *netbird.Client
		var mux *http.ServeMux
		var server *httptest.Server
		var controllerReconciler *NBRoutingPeerReconciler

		BeforeEach(func() {
			ctrl.SetLogger(logr.New(GinkgoLogr.GetSink()))
			mux = &http.ServeMux{}
			server = httptest.NewServer(mux)
			netbirdClient = netbird.New(server.URL, "ABC")
			controllerReconciler = &NBRoutingPeerReconciler{
				Client:             k8sClient,
				Scheme:             k8sClient.Scheme(),
				netbird:            netbirdClient,
				ClientImage:        "netbirdio/netbird:latest",
				ClusterName:        "kubernetes",
				DefaultLabels:      make(map[string]string),
				NamespacedNetworks: false,
			}

			By("creating the custom resource for the Kind NBRoutingPeer")
			err := k8sClient.Get(ctx, typeNamespacedName, nbroutingpeer)
			if err != nil && errors.IsNotFound(err) {
				nbroutingpeer = &netbirdiov1.NBRoutingPeer{
					ObjectMeta: metav1.ObjectMeta{
						Name:       resourceName,
						Namespace:  "default",
						Finalizers: []string{"netbird.io/cleanup"},
					},
					Spec: netbirdiov1.NBRoutingPeerSpec{
						Replicas: util.Ptr(int32(0)),
					},
				}
				Expect(k8sClient.Create(ctx, nbroutingpeer)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &netbirdiov1.NBRoutingPeer{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())

				if len(resource.Finalizers) > 0 {
					resource.Finalizers = nil
					Expect(k8sClient.Update(ctx, resource)).To(Succeed())
				}

				err = k8sClient.Delete(ctx, resource)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}

			group := &netbirdiov1.NBGroup{}
			err = k8sClient.Get(ctx, typeNamespacedName, group)
			if !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())

				if len(group.Finalizers) > 0 {
					group.Finalizers = nil
					Expect(k8sClient.Update(ctx, group)).To(Succeed())
				}

				err = k8sClient.Delete(ctx, group)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}

			deploy := &appsv1.Deployment{}
			err = k8sClient.Get(ctx, typeNamespacedName, deploy)
			if !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())

				if len(deploy.Finalizers) > 0 {
					deploy.Finalizers = nil
					Expect(k8sClient.Update(ctx, deploy)).To(Succeed())
				}

				err = k8sClient.Delete(ctx, deploy)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}

			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, typeNamespacedName, secret)
			if !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())

				if len(secret.Finalizers) > 0 {
					secret.Finalizers = nil
					Expect(k8sClient.Update(ctx, secret)).To(Succeed())
				}

				err = k8sClient.Delete(ctx, secret)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}

			nbresource := &netbirdiov1.NBResource{}
			err = k8sClient.Get(ctx, typeNamespacedName, nbresource)
			if !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())

				if len(nbresource.Finalizers) > 0 {
					nbresource.Finalizers = nil
					Expect(k8sClient.Update(ctx, nbresource)).To(Succeed())
				}

				err = k8sClient.Delete(ctx, nbresource)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}
		})

		When("Network doesn't exist", func() {
			BeforeEach(func() {
				group := &netbirdiov1.NBGroup{
					ObjectMeta: metav1.ObjectMeta{
						Name:      typeNamespacedName.Name,
						Namespace: typeNamespacedName.Namespace,
					},
					Spec: netbirdiov1.NBGroupSpec{
						Name: controllerReconciler.ClusterName,
					},
				}
				Expect(k8sClient.Create(ctx, group)).To(Succeed())
			})
			It("should create network", func() {
				networkCreated := false
				mux.HandleFunc("/api/networks", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					if r.Method == http.MethodPost {
						networkCreated = true
						var req api.PostApiNetworksJSONRequestBody
						bs, err := io.ReadAll(r.Body)
						Expect(err).NotTo(HaveOccurred())
						Expect(json.Unmarshal(bs, &req)).To(Succeed())
						Expect(req.Name).To(Equal(controllerReconciler.ClusterName))
						Expect(req.Description).NotTo(BeNil())
						Expect(req.Description).To(BeEquivalentTo(&networkDescription))
						resp := api.Network{
							Id:          "test",
							Description: req.Description,
							Name:        req.Name,
						}
						bs, err = json.Marshal(resp)
						Expect(err).NotTo(HaveOccurred())
						_, err = w.Write(bs)
						Expect(err).NotTo(HaveOccurred())
					} else if r.Method == http.MethodGet {
						_, err := w.Write([]byte("[]"))
						Expect(err).NotTo(HaveOccurred())
					}
				})
				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(networkCreated).To(BeTrue())

				Expect(k8sClient.Get(ctx, typeNamespacedName, nbroutingpeer)).To(Succeed())
				Expect(nbroutingpeer.Status.NetworkID).NotTo(BeNil())
				Expect(*nbroutingpeer.Status.NetworkID).To(Equal("test"))
			})
		})
		When("Network exists", func() {
			BeforeEach(func() {
				mux.HandleFunc("/api/networks", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					if r.Method == http.MethodGet {
						resp := []api.Network{
							{
								Id:          "test",
								Description: &networkDescription,
								Name:        controllerReconciler.ClusterName,
							},
						}
						bs, err := json.Marshal(resp)
						Expect(err).NotTo(HaveOccurred())
						_, err = w.Write(bs)
						Expect(err).NotTo(HaveOccurred())
					}
				})

				nbroutingpeer.Status.NetworkID = util.Ptr("test")
				Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())
			})
			Describe("Network Router changes", func() {
				BeforeEach(func() {
					group := &netbirdiov1.NBGroup{
						ObjectMeta: metav1.ObjectMeta{
							Name:      typeNamespacedName.Name,
							Namespace: typeNamespacedName.Namespace,
						},
						Spec: netbirdiov1.NBGroupSpec{
							Name: controllerReconciler.ClusterName,
						},
					}
					Expect(k8sClient.Create(ctx, group)).To(Succeed())

					group.Status.GroupID = util.Ptr("test")
					Expect(k8sClient.Status().Update(ctx, group)).To(Succeed())

					nbroutingpeer.Status.SetupKeyID = util.Ptr("skid")
					Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

					mux.HandleFunc("/api/setup-keys/skid", func(w http.ResponseWriter, r *http.Request) {
						defer GinkgoRecover()
						resp := api.SetupKey{
							Id:      "skid",
							Revoked: false,
						}
						bs, err := json.Marshal(resp)
						Expect(err).NotTo(HaveOccurred())
						_, err = w.Write(bs)
						Expect(err).NotTo(HaveOccurred())
					})

					secret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: typeNamespacedName.Namespace,
							Name:      typeNamespacedName.Name,
						},
						Data: map[string][]byte{
							"setupKey": []byte("SuperSecret"),
						},
					}
					Expect(k8sClient.Create(ctx, secret)).To(Succeed())
				})

				When("Network Router doesn't exist", func() {
					It("should create network router", func() {
						routerCreated := false
						mux.HandleFunc("/api/networks/test/routers", func(w http.ResponseWriter, r *http.Request) {
							defer GinkgoRecover()
							if r.Method == http.MethodPost {
								routerCreated = true
								var req api.PostApiNetworksNetworkIdRoutersJSONRequestBody
								bs, err := io.ReadAll(r.Body)
								Expect(err).NotTo(HaveOccurred())
								Expect(json.Unmarshal(bs, &req)).To(Succeed())
								Expect(req.Enabled).To(BeTrue())
								Expect(req.Masquerade).To(BeTrue())
								Expect(req.Metric).To(Equal(9999))
								Expect(req.PeerGroups).NotTo(BeNil())
								Expect(*req.PeerGroups).To(ConsistOf([]string{"test"}))

								resp := api.NetworkRouter{
									Id:         "test",
									Enabled:    true,
									Masquerade: true,
									Metric:     9999,
									PeerGroups: req.PeerGroups,
								}
								bs, err = json.Marshal(resp)
								Expect(err).NotTo(HaveOccurred())
								_, err = w.Write(bs)
								Expect(err).NotTo(HaveOccurred())
							} else if r.Method == http.MethodGet {
								resp := []api.NetworkRouter{}
								bs, err := json.Marshal(resp)
								Expect(err).NotTo(HaveOccurred())
								_, err = w.Write(bs)
								Expect(err).NotTo(HaveOccurred())
							}
						})

						_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
							NamespacedName: typeNamespacedName,
						})
						Expect(err).NotTo(HaveOccurred())
						Expect(routerCreated).To(BeTrue())

						Expect(k8sClient.Get(ctx, typeNamespacedName, nbroutingpeer)).To(Succeed())
						Expect(nbroutingpeer.Status.RouterID).NotTo(BeNil())
						Expect(*nbroutingpeer.Status.RouterID).To(Equal("test"))
					})
				})
				When("Network Router is out-of-date", func() {
					It("should update network router", func() {
						nbroutingpeer.Status.RouterID = util.Ptr("test")
						Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

						routerUpdated := false
						mux.HandleFunc("/api/networks/test/routers", func(w http.ResponseWriter, r *http.Request) {
							defer GinkgoRecover()
							if r.Method == http.MethodGet {
								resp := []api.NetworkRouter{
									{
										Id:         "test",
										Enabled:    false,
										Masquerade: false,
										Metric:     0,
										PeerGroups: &[]string{},
									},
								}
								bs, err := json.Marshal(resp)
								Expect(err).NotTo(HaveOccurred())
								_, err = w.Write(bs)
								Expect(err).NotTo(HaveOccurred())
							}
						})

						mux.HandleFunc("/api/networks/test/routers/test", func(w http.ResponseWriter, r *http.Request) {
							defer GinkgoRecover()
							if r.Method == http.MethodPut {
								routerUpdated = true
								var req api.PutApiNetworksNetworkIdRoutersRouterIdJSONRequestBody
								bs, err := io.ReadAll(r.Body)
								Expect(err).NotTo(HaveOccurred())
								Expect(json.Unmarshal(bs, &req)).To(Succeed())
								Expect(req.Enabled).To(BeTrue())
								Expect(req.Masquerade).To(BeTrue())
								Expect(req.Metric).To(Equal(9999))
								Expect(req.PeerGroups).NotTo(BeNil())
								Expect(*req.PeerGroups).To(ConsistOf([]string{"test"}))

								resp := api.NetworkRouter{
									Id:         "test",
									Enabled:    true,
									Masquerade: true,
									Metric:     9999,
									PeerGroups: req.PeerGroups,
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
						Expect(routerUpdated).To(BeTrue())

						Expect(k8sClient.Get(ctx, typeNamespacedName, nbroutingpeer)).To(Succeed())
						Expect(nbroutingpeer.Status.RouterID).NotTo(BeNil())
						Expect(*nbroutingpeer.Status.RouterID).To(Equal("test"))
					})
				})
			})
			When("Network Router exists", func() {
				BeforeEach(func() {
					nbroutingpeer.Status.RouterID = util.Ptr("test")
					Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

					mux.HandleFunc("/api/networks/test/routers", func(w http.ResponseWriter, r *http.Request) {
						defer GinkgoRecover()
						if r.Method == http.MethodGet {
							resp := []api.NetworkRouter{
								{
									Id:         "test",
									Enabled:    true,
									Masquerade: true,
									Metric:     9999,
									PeerGroups: &[]string{"test"},
								},
							}
							bs, err := json.Marshal(resp)
							Expect(err).NotTo(HaveOccurred())
							_, err = w.Write(bs)
							Expect(err).NotTo(HaveOccurred())
						}
					})
				})
				When("Group doesn't exist", func() {
					BeforeEach(func() {
						nbroutingpeer.Status.SetupKeyID = util.Ptr("skid")
						Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

						mux.HandleFunc("/api/setup-keys/skid", func(w http.ResponseWriter, r *http.Request) {
							defer GinkgoRecover()
							resp := api.SetupKey{
								Id:      "skid",
								Revoked: false,
							}
							bs, err := json.Marshal(resp)
							Expect(err).NotTo(HaveOccurred())
							_, err = w.Write(bs)
							Expect(err).NotTo(HaveOccurred())
						})

						secret := &corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: typeNamespacedName.Namespace,
								Name:      typeNamespacedName.Name,
							},
							Data: map[string][]byte{
								"setupKey": []byte("SuperSecret"),
							},
						}
						Expect(k8sClient.Create(ctx, secret)).To(Succeed())
					})
					It("should create group and requeue to get its ID", func() {
						controllerReconciler.DefaultLabels = map[string]string{"dog": "bark"}
						res, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
							NamespacedName: typeNamespacedName,
						})
						Expect(err).NotTo(HaveOccurred())
						Expect(res.RequeueAfter).To(BeNumerically(">", 0))

						group := &netbirdiov1.NBGroup{}
						Expect(k8sClient.Get(ctx, typeNamespacedName, group)).To(Succeed())
						Expect(group.Spec.Name).To(Equal(controllerReconciler.ClusterName))
						Expect(group.Labels).To(HaveKeyWithValue("dog", "bark"))

						group.Status.GroupID = util.Ptr("test")
						Expect(k8sClient.Status().Update(ctx, group)).To(Succeed())

						_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
							NamespacedName: typeNamespacedName,
						})
						Expect(err).NotTo(HaveOccurred())
					})
				})
				When("Group exists", func() {
					BeforeEach(func() {
						group := &netbirdiov1.NBGroup{
							ObjectMeta: metav1.ObjectMeta{
								Name:       typeNamespacedName.Name,
								Namespace:  typeNamespacedName.Namespace,
								Finalizers: []string{"netbird.io/routing-peer-cleanup", "netbird.io/group-cleanup"},
							},
							Spec: netbirdiov1.NBGroupSpec{
								Name: controllerReconciler.ClusterName,
							},
						}
						Expect(k8sClient.Create(ctx, group)).To(Succeed())

						group.Status.GroupID = util.Ptr("test")
						Expect(k8sClient.Status().Update(ctx, group)).To(Succeed())
					})

					Describe("Setup Key Behavior", func() {
						When("Setup key doesn't exist", func() {
							It("should create setup key and save it in Secret", func() {
								setupKeyCreated := false
								mux.HandleFunc("/api/setup-keys", func(w http.ResponseWriter, r *http.Request) {
									defer GinkgoRecover()
									if r.Method == http.MethodPost {
										setupKeyCreated = true
										var req api.PostApiSetupKeysJSONRequestBody
										bs, err := io.ReadAll(r.Body)
										Expect(err).NotTo(HaveOccurred())
										Expect(json.Unmarshal(bs, &req)).To(Succeed())
										Expect(req.AutoGroups).To(ConsistOf([]string{"test"}))
										Expect(req.Ephemeral).To(BeEquivalentTo(util.Ptr(true)))
										Expect(req.ExpiresIn).To(BeZero())
										Expect(req.Name).To(Equal(controllerReconciler.ClusterName))
										Expect(req.Type).To(Equal("reusable"))
										Expect(req.UsageLimit).To(BeZero())
										resp := api.SetupKeyClear{
											AutoGroups: req.AutoGroups,
											Ephemeral:  *req.Ephemeral,
											Id:         "test",
											Key:        "SuperSecretKey",
											Name:       req.Name,
											Valid:      true,
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
								Expect(setupKeyCreated).To(BeTrue())

								secret := &corev1.Secret{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, secret)).To(Succeed())
								Expect(secret.Data).To(HaveKey("setupKey"))
								Expect(secret.Data["setupKey"]).To(BeEquivalentTo([]byte("SuperSecretKey")))
							})
						})
						When("Setup key exists but secret is invalid", func() {
							It("should delete old setup key and requeue to regenerate", func() {
								setupKeyCreated := false
								mux.HandleFunc("/api/setup-keys", func(w http.ResponseWriter, r *http.Request) {
									defer GinkgoRecover()
									if r.Method == http.MethodPost {
										setupKeyCreated = true
										var req api.PostApiSetupKeysJSONRequestBody
										bs, err := io.ReadAll(r.Body)
										Expect(err).NotTo(HaveOccurred())
										Expect(json.Unmarshal(bs, &req)).To(Succeed())
										Expect(req.AutoGroups).To(ConsistOf([]string{"test"}))
										Expect(req.Ephemeral).To(BeEquivalentTo(util.Ptr(true)))
										Expect(req.ExpiresIn).To(BeZero())
										Expect(req.Name).To(Equal(controllerReconciler.ClusterName))
										Expect(req.Type).To(Equal("reusable"))
										Expect(req.UsageLimit).To(BeZero())
										resp := api.SetupKeyClear{
											AutoGroups: req.AutoGroups,
											Ephemeral:  *req.Ephemeral,
											Id:         "test",
											Key:        "SuperSecretKey",
											Name:       req.Name,
											Valid:      true,
										}
										bs, err = json.Marshal(resp)
										Expect(err).NotTo(HaveOccurred())
										_, err = w.Write(bs)
										Expect(err).NotTo(HaveOccurred())
									}
								})

								setupKeyDeleted := false
								mux.HandleFunc("/api/setup-keys/skid", func(w http.ResponseWriter, r *http.Request) {
									defer GinkgoRecover()
									if r.Method == http.MethodGet {
										resp := api.SetupKey{
											Id:      "skid",
											Revoked: false,
										}
										bs, err := json.Marshal(resp)
										Expect(err).NotTo(HaveOccurred())
										_, err = w.Write(bs)
										Expect(err).NotTo(HaveOccurred())
									} else if r.Method == http.MethodDelete {
										setupKeyDeleted = true
										_, err := w.Write([]byte(`{}`))
										Expect(err).NotTo(HaveOccurred())
									}
								})

								nbroutingpeer.Status.SetupKeyID = util.Ptr("skid")
								Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

								res, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								Expect(res.Requeue).To(BeTrue())
								Expect(setupKeyDeleted).To(BeTrue())

								_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								Expect(setupKeyCreated).To(BeTrue())

								secret := &corev1.Secret{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, secret)).To(Succeed())
								Expect(secret.Data).To(HaveKey("setupKey"))
								Expect(secret.Data["setupKey"]).To(BeEquivalentTo([]byte("SuperSecretKey")))
							})
						})
						When("Setup key is revoked", func() {
							It("should delete setup key and requeue to recreate", func() {
								setupKeyCreated := false
								mux.HandleFunc("/api/setup-keys", func(w http.ResponseWriter, r *http.Request) {
									defer GinkgoRecover()
									if r.Method == http.MethodPost {
										setupKeyCreated = true
										var req api.PostApiSetupKeysJSONRequestBody
										bs, err := io.ReadAll(r.Body)
										Expect(err).NotTo(HaveOccurred())
										Expect(json.Unmarshal(bs, &req)).To(Succeed())
										Expect(req.AutoGroups).To(ConsistOf([]string{"test"}))
										Expect(req.Ephemeral).To(BeEquivalentTo(util.Ptr(true)))
										Expect(req.ExpiresIn).To(BeZero())
										Expect(req.Name).To(Equal(controllerReconciler.ClusterName))
										Expect(req.Type).To(Equal("reusable"))
										Expect(req.UsageLimit).To(BeZero())
										resp := api.SetupKeyClear{
											AutoGroups: req.AutoGroups,
											Ephemeral:  *req.Ephemeral,
											Id:         "test",
											Key:        "SuperSecretKey",
											Name:       req.Name,
											Valid:      true,
										}
										bs, err = json.Marshal(resp)
										Expect(err).NotTo(HaveOccurred())
										_, err = w.Write(bs)
										Expect(err).NotTo(HaveOccurred())
									}
								})

								setupKeyDeleted := false
								mux.HandleFunc("/api/setup-keys/skid", func(w http.ResponseWriter, r *http.Request) {
									defer GinkgoRecover()
									if r.Method == http.MethodGet {
										resp := api.SetupKey{
											Id:      "skid",
											Revoked: true,
										}
										bs, err := json.Marshal(resp)
										Expect(err).NotTo(HaveOccurred())
										_, err = w.Write(bs)
										Expect(err).NotTo(HaveOccurred())
									} else if r.Method == http.MethodDelete {
										setupKeyDeleted = true
										_, err := w.Write([]byte(`{}`))
										Expect(err).NotTo(HaveOccurred())
									}
								})

								nbroutingpeer.Status.SetupKeyID = util.Ptr("skid")
								Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

								secret := &corev1.Secret{
									ObjectMeta: metav1.ObjectMeta{
										Namespace: typeNamespacedName.Namespace,
										Name:      typeNamespacedName.Name,
									},
									StringData: map[string]string{
										"setupKey": "GoneKey",
									},
								}
								Expect(k8sClient.Create(ctx, secret)).To(Succeed())

								res, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								Expect(res.Requeue).To(BeTrue())
								Expect(setupKeyDeleted).To(BeTrue())

								_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								Expect(setupKeyCreated).To(BeTrue())

								secret = &corev1.Secret{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, secret)).To(Succeed())
								Expect(secret.Data).To(HaveKey("setupKey"))
								Expect(secret.Data["setupKey"]).To(BeEquivalentTo([]byte("SuperSecretKey")))
							})
						})
						When("Setup key is deleted", func() {
							It("should requeue to recreate", func() {
								setupKeyCreated := false
								mux.HandleFunc("/api/setup-keys", func(w http.ResponseWriter, r *http.Request) {
									defer GinkgoRecover()
									if r.Method == http.MethodPost {
										setupKeyCreated = true
										var req api.PostApiSetupKeysJSONRequestBody
										bs, err := io.ReadAll(r.Body)
										Expect(err).NotTo(HaveOccurred())
										Expect(json.Unmarshal(bs, &req)).To(Succeed())
										Expect(req.AutoGroups).To(ConsistOf([]string{"test"}))
										Expect(req.Ephemeral).To(BeEquivalentTo(util.Ptr(true)))
										Expect(req.ExpiresIn).To(BeZero())
										Expect(req.Name).To(Equal(controllerReconciler.ClusterName))
										Expect(req.Type).To(Equal("reusable"))
										Expect(req.UsageLimit).To(BeZero())
										resp := api.SetupKeyClear{
											AutoGroups: req.AutoGroups,
											Ephemeral:  *req.Ephemeral,
											Id:         "test",
											Key:        "SuperSecretKey",
											Name:       req.Name,
											Valid:      true,
										}
										bs, err = json.Marshal(resp)
										Expect(err).NotTo(HaveOccurred())
										_, err = w.Write(bs)
										Expect(err).NotTo(HaveOccurred())
									}
								})

								setupKeyDeleted := false
								mux.HandleFunc("/api/setup-keys/skid", func(w http.ResponseWriter, r *http.Request) {
									defer GinkgoRecover()
									if r.Method == http.MethodGet {
										w.WriteHeader(404)
										_, err := w.Write([]byte(`{"message": "setup-key skid not found", "code": 404}`))
										Expect(err).NotTo(HaveOccurred())
									} else if r.Method == http.MethodDelete {
										setupKeyDeleted = true
										_, err := w.Write([]byte(`{}`))
										Expect(err).NotTo(HaveOccurred())
									}
								})

								nbroutingpeer.Status.SetupKeyID = util.Ptr("skid")
								Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

								secret := &corev1.Secret{
									ObjectMeta: metav1.ObjectMeta{
										Namespace: typeNamespacedName.Namespace,
										Name:      typeNamespacedName.Name,
									},
									StringData: map[string]string{
										"setupKey": "GoneKey",
									},
								}
								Expect(k8sClient.Create(ctx, secret)).To(Succeed())

								res, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								Expect(res.Requeue).To(BeTrue())
								Expect(setupKeyDeleted).To(BeFalse())

								_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								Expect(setupKeyCreated).To(BeTrue())

								secret = &corev1.Secret{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, secret)).To(Succeed())
								Expect(secret.Data).To(HaveKey("setupKey"))
								Expect(secret.Data["setupKey"]).To(BeEquivalentTo([]byte("SuperSecretKey")))
							})
						})
						When("Setup key exists and is valid", func() {
							It("should do nothing", func() {
								setupKeyDeleted := false
								mux.HandleFunc("/api/setup-keys/skid", func(w http.ResponseWriter, r *http.Request) {
									defer GinkgoRecover()
									if r.Method == http.MethodGet {
										resp := api.SetupKey{
											Id:      "skid",
											Revoked: false,
										}
										bs, err := json.Marshal(resp)
										Expect(err).NotTo(HaveOccurred())
										_, err = w.Write(bs)
										Expect(err).NotTo(HaveOccurred())
									} else if r.Method == http.MethodDelete {
										setupKeyDeleted = true
										_, err := w.Write([]byte(`{}`))
										Expect(err).NotTo(HaveOccurred())
									}
								})

								nbroutingpeer.Status.SetupKeyID = util.Ptr("skid")
								Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

								secret := &corev1.Secret{
									ObjectMeta: metav1.ObjectMeta{
										Namespace: typeNamespacedName.Namespace,
										Name:      typeNamespacedName.Name,
									},
									StringData: map[string]string{
										"setupKey": "OriginalKey",
									},
								}
								Expect(k8sClient.Create(ctx, secret)).To(Succeed())

								res, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								Expect(res.Requeue).To(BeFalse())
								Expect(setupKeyDeleted).To(BeFalse())

								secret = &corev1.Secret{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, secret)).To(Succeed())
								Expect(secret.Data).To(HaveKey("setupKey"))
								Expect(secret.Data["setupKey"]).To(BeEquivalentTo([]byte("OriginalKey")))
							})
						})
					})
					Describe("Deployment Behavior", func() {
						BeforeEach(func() {
							nbroutingpeer.Status.SetupKeyID = util.Ptr("skid")
							Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

							mux.HandleFunc("/api/setup-keys/skid", func(w http.ResponseWriter, r *http.Request) {
								defer GinkgoRecover()
								resp := api.SetupKey{
									Id:      "skid",
									Revoked: false,
								}
								bs, err := json.Marshal(resp)
								Expect(err).NotTo(HaveOccurred())
								_, err = w.Write(bs)
								Expect(err).NotTo(HaveOccurred())
							})

							secret := &corev1.Secret{
								ObjectMeta: metav1.ObjectMeta{
									Namespace: typeNamespacedName.Namespace,
									Name:      typeNamespacedName.Name,
								},
								Data: map[string][]byte{
									"setupKey": []byte("SuperSecret"),
								},
							}
							Expect(k8sClient.Create(ctx, secret)).To(Succeed())
						})

						When("Deployment doesn't exist", func() {
							It("should create deployment", func() {
								_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())

								deployment := &appsv1.Deployment{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, deployment)).To(Succeed())
								Expect(deployment.OwnerReferences).To(HaveLen(1))
								Expect(deployment.Spec.Replicas).To(BeEquivalentTo(util.Ptr(int32(0))))
								Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
								Expect(deployment.Spec.Template.Spec.Containers[0].Image).To(Equal(controllerReconciler.ClientImage))
							})
						})

						When("Default labels exist", func() {
							It("should add labels to Deployment and Pod metadata", func() {
								controllerReconciler.DefaultLabels = map[string]string{
									"cat": "meow",
									"dog": "bark",
								}
								_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())

								deployment := &appsv1.Deployment{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, deployment)).To(Succeed())
								Expect(deployment.Labels).To(HaveKeyWithValue("cat", "meow"))
								Expect(deployment.Labels).To(HaveKeyWithValue("dog", "bark"))
							})
						})

						When("Deployment is out-of-date", func() {
							It("should update deployment", func() {
								_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())

								deployment := &appsv1.Deployment{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, deployment)).To(Succeed())
								deployment.Spec.Replicas = util.Ptr(int32(15))
								Expect(k8sClient.Update(ctx, deployment)).To(Succeed())

								_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								deployment = &appsv1.Deployment{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, deployment)).To(Succeed())
								Expect(deployment.Spec.Replicas).To(BeEquivalentTo(util.Ptr(int32(0))))
							})
						})
						When("Deployment is up-to-date", func() {
							It("should ", func() {
								_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())

								deployment := &appsv1.Deployment{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, deployment)).To(Succeed())
								resourceVersion := deployment.ResourceVersion

								_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								deployment = &appsv1.Deployment{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, deployment)).To(Succeed())
								Expect(deployment.ResourceVersion).To(Equal(resourceVersion))
							})
						})
					})
					When("NBRoutingPeer is set for deletion", func() {
						networkDeleted := false
						routerDeleted := false
						BeforeEach(func() {
							networkDeleted = false
							routerDeleted = false
							nbroutingpeer.Status.SetupKeyID = util.Ptr("skid")
							Expect(k8sClient.Status().Update(ctx, nbroutingpeer)).To(Succeed())

							mux.HandleFunc("/api/setup-keys/skid", func(w http.ResponseWriter, r *http.Request) {
								defer GinkgoRecover()
								resp := api.SetupKey{
									Id:      "skid",
									Revoked: false,
								}
								bs, err := json.Marshal(resp)
								Expect(err).NotTo(HaveOccurred())
								_, err = w.Write(bs)
								Expect(err).NotTo(HaveOccurred())
							})

							secret := &corev1.Secret{
								ObjectMeta: metav1.ObjectMeta{
									Namespace: typeNamespacedName.Namespace,
									Name:      typeNamespacedName.Name,
								},
								Data: map[string][]byte{
									"setupKey": []byte("SuperSecret"),
								},
							}
							Expect(k8sClient.Create(ctx, secret)).To(Succeed())
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())

							mux.HandleFunc("/api/networks/test", func(w http.ResponseWriter, r *http.Request) {
								defer GinkgoRecover()
								Expect(r.Method).To(Equal(http.MethodDelete))
								_, err = w.Write([]byte(`{}`))
								Expect(err).NotTo(HaveOccurred())
								networkDeleted = true
							})

							mux.HandleFunc("/api/networks/test/routers/test", func(w http.ResponseWriter, r *http.Request) {
								defer GinkgoRecover()
								Expect(r.Method).To(Equal(http.MethodDelete))
								_, err = w.Write([]byte(`{}`))
								Expect(err).NotTo(HaveOccurred())
								routerDeleted = true
							})
						})

						It("should remove finalizer from NBGroup", func() {
							Expect(k8sClient.Delete(ctx, nbroutingpeer)).To(Succeed())
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())
							group := &netbirdiov1.NBGroup{}
							Expect(k8sClient.Get(ctx, typeNamespacedName, group)).To(Succeed())
							Expect(group.Finalizers).NotTo(ContainElement("netbird.io/routing-peer-cleanup"))
						})

						It("should delete Network Router", func() {
							Expect(k8sClient.Delete(ctx, nbroutingpeer)).To(Succeed())
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())
							Expect(routerDeleted).To(BeTrue())
						})

						It("should delete Network", func() {
							Expect(k8sClient.Delete(ctx, nbroutingpeer)).To(Succeed())
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())
							Expect(networkDeleted).To(BeTrue())
						})

						It("should delete deployment", func() {
							Expect(k8sClient.Delete(ctx, nbroutingpeer)).To(Succeed())
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())
							deployment := &appsv1.Deployment{}
							err = k8sClient.Get(ctx, typeNamespacedName, deployment)
							Expect(errors.IsNotFound(err)).To(BeTrue())
						})

						It("should delete any hanging NBResources", func() {
							nbResource := &netbirdiov1.NBResource{
								ObjectMeta: metav1.ObjectMeta{
									Name:      typeNamespacedName.Name,
									Namespace: typeNamespacedName.Namespace,
								},
								Spec: netbirdiov1.NBResourceSpec{
									Name:      "test",
									NetworkID: *nbroutingpeer.Status.NetworkID,
									Address:   "test",
									Groups:    []string{"grp"},
								},
							}
							Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())
							Expect(k8sClient.Delete(ctx, nbroutingpeer)).To(Succeed())
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())
							nbResource = &netbirdiov1.NBResource{}
							err = k8sClient.Get(ctx, typeNamespacedName, nbResource)
							Expect(errors.IsNotFound(err)).To(BeTrue())
						})
					})
				})
			})
		})
	})
})
