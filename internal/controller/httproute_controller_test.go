// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

var _ = Describe("HTTPRoute Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			resourceName     = "test-httproute"
			gatewayClassName = "test-gatewayclass"
			gatewayName      = "test-gateway"
			routerName       = "test-router"
			serviceName      = "test-service"
			namespace        = "default"
		)

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: namespace,
		}

		var (
			netbirdClient *netbird.Client
			mux           *http.ServeMux
			server        *httptest.Server
			httpRoute     *gwv1.HTTPRoute
			gatewayClass  *gwv1.GatewayClass
			gateway       *gwv1.Gateway
			netRouter     *nbv1alpha1.NetworkRouter
			service       *corev1.Service
		)

		BeforeEach(func() {
			mux = &http.ServeMux{}
			server = httptest.NewServer(mux)
			netbirdClient = netbird.New(server.URL, "ABC")

			// Setup GatewayClass
			gatewayClass = &gwv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: gatewayClassName,
				},
				Spec: gwv1.GatewayClassSpec{
					ControllerName: gwv1.GatewayController(GatewayControllerName),
				},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: gatewayClassName}, gatewayClass)
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, gatewayClass)).To(Succeed())
			}

			// Setup NetworkRouter
			netRouter = &nbv1alpha1.NetworkRouter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routerName,
					Namespace: namespace,
				},
				Spec: nbv1alpha1.NetworkRouterSpec{
					DNSZoneRef: nbv1alpha1.DNSZoneReference{
						Name: "prod.company.internal",
					},
				},
			}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: routerName, Namespace: namespace}, netRouter)
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, netRouter)).To(Succeed())
			}

			// Setup Gateway
			gatewaySpec := gwv1.GatewaySpec{
				GatewayClassName: gwv1.ObjectName(gatewayClassName),
				Listeners: []gwv1.Listener{
					{
						Name:     gwv1.SectionName(routerName),
						Protocol: gwv1.ProtocolType("gateway.netbird.io/NetworkRouter"),
						Port:     gwv1.PortNumber(1),
					},
				},
			}

			gateway = &gwv1.Gateway{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: namespace}, gateway)
			if err != nil {
				if errors.IsNotFound(err) {
					gateway = &gwv1.Gateway{
						ObjectMeta: metav1.ObjectMeta{
							Name:      gatewayName,
							Namespace: namespace,
						},
						Spec: gatewaySpec,
					}
					Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
				} else {
					Expect(err).NotTo(HaveOccurred())
				}
			} else {
				gateway.Spec = gatewaySpec
				Expect(k8sClient.Update(ctx, gateway)).To(Succeed())
			}

			gateway.Status.Conditions = []metav1.Condition{
				{
					Type:               string(gwv1.GatewayConditionProgrammed),
					Status:             metav1.ConditionTrue,
					Reason:             "Programmed",
					LastTransitionTime: metav1.Now(),
				},
			}
			Expect(k8sClient.Status().Update(ctx, gateway)).To(Succeed())

			// Setup Service
			serviceSpec := corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{
						Name: "http",
						Port: 8080,
					},
				},
			}
			service = &corev1.Service{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: namespace}, service)
			if err != nil {
				if errors.IsNotFound(err) {
					service = &corev1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:      serviceName,
							Namespace: namespace,
						},
						Spec: serviceSpec,
					}
					Expect(k8sClient.Create(ctx, service)).To(Succeed())
				} else {
					Expect(err).NotTo(HaveOccurred())
				}
			} else {
				service.Spec = serviceSpec
				Expect(k8sClient.Update(ctx, service)).To(Succeed())
			}

			kindService := gwv1.Kind("Service")
			nsDefault := gwv1.Namespace(namespace)
			port80 := gwv1.PortNumber(8080)

			// Setup HTTPRoute
			httpRoute = &gwv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: gwv1.HTTPRouteSpec{
					CommonRouteSpec: gwv1.CommonRouteSpec{
						ParentRefs: []gwv1.ParentReference{
							{
								Name: gwv1.ObjectName(gatewayName),
							},
						},
					},
					Hostnames: []gwv1.Hostname{"test.example.com"},
					Rules: []gwv1.HTTPRouteRule{
						{
							BackendRefs: []gwv1.HTTPBackendRef{
								{
									BackendRef: gwv1.BackendRef{
										BackendObjectReference: gwv1.BackendObjectReference{
											Kind:      &kindService,
											Name:      gwv1.ObjectName(serviceName),
											Namespace: &nsDefault,
											Port:      &port80,
										},
									},
								},
							},
						},
					},
				},
			}

			err = k8sClient.Get(ctx, typeNamespacedName, httpRoute)
			if err == nil {
				Expect(k8sClient.Delete(ctx, httpRoute)).To(Succeed())
			}
		})

		AfterEach(func() {
			server.Close()
			// Clean up HTTPRoute if it exists
			hr := &gwv1.HTTPRoute{}
			err := k8sClient.Get(ctx, typeNamespacedName, hr)
			if err == nil {
				if len(hr.Finalizers) > 0 {
					hr.Finalizers = nil
					Expect(k8sClient.Update(ctx, hr)).To(Succeed())
				}
				Expect(k8sClient.Delete(ctx, hr)).To(Succeed())
			}

			// Clean up NetworkResource if created
			netRes := &nbv1alpha1.NetworkResource{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: namespace}, netRes)
			if err == nil {
				Expect(k8sClient.Delete(ctx, netRes)).To(Succeed())
			}
		})

		It("should ignore HTTPRoute that does not exist", func() {
			reconciler := &HTTPRouteReconciler{
				Client:  k8sClient,
				Netbird: netbirdClient,
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent-route",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should do nothing if parent Gateway is not programmed", func() {
			// Update gateway to be unprogrammed
			gw := &gwv1.Gateway{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: namespace}, gw)).To(Succeed())
			gw.Status.Conditions = []metav1.Condition{
				{
					Type:               string(gwv1.GatewayConditionProgrammed),
					Status:             metav1.ConditionFalse,
					Reason:             "NotProgrammed",
					LastTransitionTime: metav1.Now(),
				},
			}
			Expect(k8sClient.Status().Update(ctx, gw)).To(Succeed())

			Expect(k8sClient.Create(ctx, httpRoute)).To(Succeed())

			reconciler := &HTTPRouteReconciler{
				Client:  k8sClient,
				Netbird: netbirdClient,
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			// Check that no finalizers are added
			hr := &gwv1.HTTPRoute{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, hr)).To(Succeed())
			Expect(hr.Finalizers).To(BeEmpty())
		})

		It("should return error if referenced Service does not exist", func() {
			httpRoute.Spec.Rules[0].BackendRefs[0].BackendRef.Name = "missing-service"
			Expect(k8sClient.Create(ctx, httpRoute)).To(Succeed())

			reconciler := &HTTPRouteReconciler{
				Client:  k8sClient,
				Netbird: netbirdClient,
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).To(HaveOccurred())
		})

		It("should requeue when NetworkResource is created but not yet Ready", func() {
			Expect(k8sClient.Create(ctx, httpRoute)).To(Succeed())

			reconciler := &HTTPRouteReconciler{
				Client:  k8sClient,
				Netbird: netbirdClient,
			}
			res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(Equal(1 * time.Second))

			// Verify that NetworkResource was created
			netRes := &nbv1alpha1.NetworkResource{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: namespace}, netRes)).To(Succeed())
			Expect(netRes.OwnerReferences).To(HaveLen(2))
		})

		Context("When NetworkResource is ready", func() {
			var netRes *nbv1alpha1.NetworkResource

			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, httpRoute)).To(Succeed())

				// Pre-create and set NetworkResource as Ready
				netRes = &nbv1alpha1.NetworkResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serviceName,
						Namespace: namespace,
					},
					Spec: nbv1alpha1.NetworkResourceSpec{
						NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{
							Name:      routerName,
							Namespace: namespace,
						},
						ServiceRef: corev1.LocalObjectReference{
							Name: serviceName,
						},
					},
				}
				Expect(k8sClient.Create(ctx, netRes)).To(Succeed())

				netRes.Status.ResourceID = "net-resource-id"
				netRes.Status.Conditions = []metav1.Condition{
					{
						Type:               "Ready",
						Status:             metav1.ConditionTrue,
						Reason:             "Ready",
						LastTransitionTime: metav1.Now(),
					},
				}
				Expect(k8sClient.Status().Update(ctx, netRes)).To(Succeed())
			})

			It("should reconcile and create/update NetBird Reverse Proxy Service", func() {
				reconciler := &HTTPRouteReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				listCalled := false
				createCalled := false
				mux.HandleFunc("GET /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					listCalled = true
					resp := []api.Service{}
					bs, _ := json.Marshal(resp)
					_, _ = w.Write(bs)
				})

				mux.HandleFunc("POST /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					createCalled = true
					var req api.ServiceRequest
					Expect(json.NewDecoder(r.Body).Decode(&req)).To(Succeed())
					Expect(req.Domain).To(Equal("test.example.com"))
					Expect(*req.Targets).To(HaveLen(1))
					Expect((*req.Targets)[0].TargetId).To(Equal("net-resource-id"))
					Expect((*req.Targets)[0].Port).To(Equal(8080))

					resp := api.Service{
						Id:     "proxy-service-id",
						Domain: "test.example.com",
					}
					bs, _ := json.Marshal(resp)
					_, _ = w.Write(bs)
				})

				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				Expect(err).NotTo(HaveOccurred())
				Expect(listCalled).To(BeTrue())
				Expect(createCalled).To(BeTrue())

				// Verify that finalizer is added
				hr := &gwv1.HTTPRoute{}
				Expect(k8sClient.Get(ctx, typeNamespacedName, hr)).To(Succeed())
				Expect(hr.Finalizers).To(ContainElement("finalizers.netbird.io/httproute"))
			})

			It("should default Kind to Service if BackendRef Kind is nil/empty", func() {
				// Re-create HTTPRoute with nil/unset Kind
				Expect(k8sClient.Delete(ctx, httpRoute)).To(Succeed())
				httpRoute.ObjectMeta.ResourceVersion = ""
				httpRoute.Spec.Rules[0].BackendRefs[0].BackendRef.Kind = nil

				Expect(k8sClient.Create(ctx, httpRoute)).To(Succeed())

				reconciler := &HTTPRouteReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				createCalled := false
				mux.HandleFunc("GET /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("[]"))
				})

				mux.HandleFunc("POST /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					createCalled = true
					resp := api.Service{Id: "proxy-service-id", Domain: "test.example.com"}
					_ = json.NewEncoder(w).Encode(resp)
				})

				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				Expect(err).NotTo(HaveOccurred())
				Expect(createCalled).To(BeTrue(), "reconcile should proceed since unset Kind defaults to Service")
			})

			It("should skip BackendRefs with unsupported Kind", func() {
				// Re-create HTTPRoute with unsupported Kind "Secret"
				Expect(k8sClient.Delete(ctx, httpRoute)).To(Succeed())
				httpRoute.ObjectMeta.ResourceVersion = ""
				*httpRoute.Spec.Rules[0].BackendRefs[0].BackendRef.Kind = "Secret"

				Expect(k8sClient.Create(ctx, httpRoute)).To(Succeed())

				reconciler := &HTTPRouteReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				mux.HandleFunc("GET /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("[]"))
				})

				mux.HandleFunc("POST /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					var req api.ServiceRequest
					Expect(json.NewDecoder(r.Body).Decode(&req)).To(Succeed())
					Expect(*req.Targets).To(BeEmpty())

					resp := api.Service{Id: "proxy-service-id", Domain: "test.example.com"}
					_ = json.NewEncoder(w).Encode(resp)
				})

				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should create ServiceTarget resources for multiple path matches", func() {
				// Re-create HTTPRoute with multiple path matches
				Expect(k8sClient.Delete(ctx, httpRoute)).To(Succeed())
				httpRoute.ObjectMeta.ResourceVersion = ""

				pathPrefix := gwv1.PathMatchPathPrefix
				path1 := gwv1.HTTPRouteMatch{
					Path: &gwv1.HTTPPathMatch{
						Type:  &pathPrefix,
						Value: new("/api"),
					},
				}
				path2 := gwv1.HTTPRouteMatch{
					Path: &gwv1.HTTPPathMatch{
						Type:  &pathPrefix,
						Value: new("/admin"),
					},
				}
				httpRoute.Spec.Rules[0].Matches = []gwv1.HTTPRouteMatch{path1, path2}

				Expect(k8sClient.Create(ctx, httpRoute)).To(Succeed())

				reconciler := &HTTPRouteReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				createCalled := false
				mux.HandleFunc("GET /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("[]"))
				})

				mux.HandleFunc("POST /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					createCalled = true
					var req api.ServiceRequest
					Expect(json.NewDecoder(r.Body).Decode(&req)).To(Succeed())
					Expect(req.Domain).To(Equal("test.example.com"))
					Expect(*req.Targets).To(HaveLen(2))

					// Verify that both paths are created as separate targets
					paths := []string{}
					for _, target := range *req.Targets {
						if target.Path != nil {
							paths = append(paths, *target.Path)
						}
					}
					Expect(paths).To(ContainElements("/api", "/admin"))

					// Verify that targets have the correct options
					for _, target := range *req.Targets {
						Expect(target.Port).To(Equal(8080))
						Expect(target.TargetId).To(Equal("net-resource-id"))
						Expect(target.Protocol).To(Equal(api.ServiceTargetProtocolHttp))
						Expect(target.TargetType).To(Equal(api.ServiceTargetTargetTypeHost))
						Expect(target.Enabled).To(BeTrue())
						// If path is set, options should be set with path rewrite preserve
						if target.Path != nil {
							Expect(target.Options).NotTo(BeNil())
							Expect(target.Options.PathRewrite).NotTo(BeNil())
						}
					}

					resp := api.Service{
						Id:     "proxy-service-id",
						Domain: "test.example.com",
					}
					_ = json.NewEncoder(w).Encode(resp)
				})

				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				Expect(err).NotTo(HaveOccurred())
				Expect(createCalled).To(BeTrue())

				// Verify that finalizer is added
				hr := &gwv1.HTTPRoute{}
				Expect(k8sClient.Get(ctx, typeNamespacedName, hr)).To(Succeed())
				Expect(hr.Finalizers).To(ContainElement("finalizers.netbird.io/httproute"))
			})

			It("should clean up resources on deletion", func() {
				// Add finalizer to httpRoute
				hr := &gwv1.HTTPRoute{}
				Expect(k8sClient.Get(ctx, typeNamespacedName, hr)).To(Succeed())
				hr.Finalizers = []string{"finalizers.netbird.io/httproute"}
				Expect(k8sClient.Update(ctx, hr)).To(Succeed())

				// Add HTTPRoute as owner to NetworkResource
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: namespace}, netRes)).To(Succeed())
				netRes.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: "gateway.networking.k8s.io/v1",
						Kind:       "HTTPRoute",
						Name:       resourceName,
						UID:        hr.UID,
					},
				}
				Expect(k8sClient.Update(ctx, netRes)).To(Succeed())

				// Mark HTTPRoute for deletion
				Expect(k8sClient.Delete(ctx, hr)).To(Succeed())

				reconciler := &HTTPRouteReconciler{
					Client:  k8sClient,
					Netbird: netbirdClient,
				}

				listCalled := false
				deleteCalled := false
				mux.HandleFunc("GET /api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
					listCalled = true
					resp := []api.Service{
						{
							Id:     "proxy-service-id",
							Domain: "test.example.com",
						},
					}
					_ = json.NewEncoder(w).Encode(resp)
				})
				mux.HandleFunc("DELETE /api/reverse-proxies/services/proxy-service-id", func(w http.ResponseWriter, r *http.Request) {
					deleteCalled = true
					w.WriteHeader(http.StatusOK)
				})

				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				Expect(err).NotTo(HaveOccurred())
				Expect(listCalled).To(BeTrue())
				Expect(deleteCalled).To(BeTrue())

				// Verify that NetworkResource is deleted since HTTPRoute was the only owner reference
				netResCheck := &nbv1alpha1.NetworkResource{}
				err = k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: namespace}, netResCheck)
				Expect(errors.IsNotFound(err)).To(BeTrue())

				// Verify HTTPRoute is deleted
				hrCheck := &gwv1.HTTPRoute{}
				err = k8sClient.Get(ctx, typeNamespacedName, hrCheck)
				Expect(errors.IsNotFound(err)).To(BeTrue())
			})
		})
	})
})
