// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"errors"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

var _ = Describe("HTTPRoute Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var httpRouteRec *HTTPRouteReconciler

		// envtest does not run a namespace controller, so namespace deletion
		// is not cascaded. Use a dedicated namespace per spec to avoid name
		// collisions between specs.
		setup := func(namespace string) client.ObjectKey {
			nn := client.ObjectKey{
				Name:      "test-resource",
				Namespace: namespace,
			}

			nbClient := netbirdmock.Client()
			httpRouteRec = &HTTPRouteReconciler{
				Client:  k8sClient,
				Netbird: nbClient,
			}

			create := func(obj client.Object) {
				Eventually(func() error {
					err := k8sClient.Create(ctx, obj.DeepCopyObject().(client.Object))
					if kerrors.IsAlreadyExists(err) {
						return errors.New("waiting for terminating object to be deleted")
					}
					return err
				}, 30*time.Second, time.Second).Should(Succeed())
			}

			create(&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			})

			for _, class := range []string{GatewayClassNamePublic, GatewayClassNamePrivate} {
				create(&gwv1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: class,
					},
					Spec: gwv1.GatewayClassSpec{
						ControllerName: gwv1.GatewayController(GatewayControllerName),
					},
				})
			}

			for _, class := range []string{GatewayClassNamePublic, GatewayClassNamePrivate} {
				gw := &gwv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      class,
						Namespace: namespace,
					},
					Spec: gwv1.GatewaySpec{
						GatewayClassName: gwv1.ObjectName(class),
						Listeners: []gwv1.Listener{
							{
								Name:     "router",
								Protocol: gwv1.ProtocolType("gateway.netbird.io/NetworkRouter"),
								Port:     1,
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, gw)).To(Succeed())

				got := &gwv1.Gateway{}
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gw), got)).To(Succeed())
				meta.SetStatusCondition(&got.Status.Conditions, metav1.Condition{
					Type:   string(gwv1.GatewayConditionProgrammed),
					Status: metav1.ConditionTrue,
					Reason: string(gwv1.GatewayReasonProgrammed),
				})
				Expect(k8sClient.Status().Update(ctx, got)).To(Succeed())
			}

			netRouter := &nbv1alpha1.NetworkRouter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "router",
					Namespace: namespace,
				},
				Spec: nbv1alpha1.NetworkRouterSpec{
					DNSZoneRef: nbv1alpha1.DNSZoneReference{
						Name: "cluster.local",
					},
				},
			}
			Expect(k8sClient.Create(ctx, netRouter)).To(Succeed())

			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "backend",
					Namespace: namespace,
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:     "http",
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, svc)).To(Succeed())

			return nn
		}

		cleanup := func(nn client.ObjectKey) {
			// Delete every route and gateway created by the spec so
			// cluster-wide lists in later specs are not polluted.
			for _, name := range []string{nn.Name, "test-resource-2"} {
				hr := &gwv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: nn.Namespace,
					},
				}
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(hr), hr); err == nil {
					hr.Finalizers = nil
					Expect(k8sClient.Update(ctx, hr)).To(Succeed())
					Expect(k8sClient.Delete(ctx, hr)).To(Succeed())
				}
			}
			for _, class := range []string{GatewayClassNamePublic, GatewayClassNamePrivate} {
				gw := &gwv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      class,
						Namespace: nn.Namespace,
					},
				}
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, gw))).To(Succeed())
				gwc := &gwv1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: class,
					},
				}
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, gwc))).To(Succeed())
			}
		}

		createRoute := func(nn client.ObjectKey, gateway string) {
			pathType := gwv1.PathMatchPathPrefix
			pathValue := "/"
			hr := &gwv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: gwv1.HTTPRouteSpec{
					CommonRouteSpec: gwv1.CommonRouteSpec{
						ParentRefs: []gwv1.ParentReference{
							{
								Name: gwv1.ObjectName(gateway),
							},
						},
					},
					Hostnames: []gwv1.Hostname{
						"test.example.com",
					},
					Rules: []gwv1.HTTPRouteRule{
						{
							BackendRefs: []gwv1.HTTPBackendRef{
								{
									BackendRef: gwv1.BackendRef{
										BackendObjectReference: gwv1.BackendObjectReference{
											Name: "backend",
											Port: ptr(int32(80)),
										},
									},
								},
							},
							Matches: []gwv1.HTTPRouteMatch{
								{
									Path: &gwv1.HTTPPathMatch{
										Type:  &pathType,
										Value: &pathValue,
									},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, hr)).To(Succeed())
		}

		markResourceReady := func(nn client.ObjectKey) {
			netResource := &nbv1alpha1.NetworkResource{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: nn.Namespace, Name: "backend"}, netResource)).To(Succeed())
			conditions.MarkTrue(netResource, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
			Expect(k8sClient.Status().Update(ctx, netResource)).To(Succeed())
		}

		It("creates a public reverse proxy service for public gateways", func() {
			nn := setup("http-route-public")
			defer cleanup(nn)

			createRoute(nn, GatewayClassNamePublic)

			_, err := httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			netResource := &nbv1alpha1.NetworkResource{}
			err = k8sClient.Get(ctx, client.ObjectKey{Namespace: nn.Namespace, Name: "backend"}, netResource)
			Expect(err).NotTo(HaveOccurred())

			markResourceReady(nn)

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			hr := &gwv1.HTTPRoute{}
			Expect(k8sClient.Get(ctx, nn, hr)).To(Succeed())

			services, err := httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(HaveLen(1))
			Expect(services[0].Domain).To(Equal("test.example.com"))
			Expect(services[0].Name).To(Equal(proxyServiceName("test.example.com", string(hr.UID))))
			Expect(services[0].Enabled).To(BeTrue())
			Expect(services[0].Private).ToNot(BeNil())
			Expect(*services[0].Private).To(BeFalse())
		})

		It("creates a private reverse proxy service for private gateways", func() {
			nn := setup("http-route-private")
			defer cleanup(nn)

			createRoute(nn, GatewayClassNamePrivate)

			_, err := httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			netResource := &nbv1alpha1.NetworkResource{}
			err = k8sClient.Get(ctx, client.ObjectKey{Namespace: nn.Namespace, Name: "backend"}, netResource)
			Expect(err).NotTo(HaveOccurred())

			markResourceReady(nn)

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			services, err := httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(HaveLen(1))
			Expect(services[0].Domain).To(Equal("test.example.com"))
			Expect(services[0].Private).ToNot(BeNil())
			Expect(*services[0].Private).To(BeTrue())
			// No group annotation on the backend, so access defaults to denied.
			Expect(services[0].AccessGroups).ToNot(BeNil())
			Expect(*services[0].AccessGroups).To(BeEmpty())

			// Deleting the route removes the private service.
			hr := &gwv1.HTTPRoute{}
			Expect(k8sClient.Get(ctx, nn, hr)).To(Succeed())
			Expect(k8sClient.Delete(ctx, hr)).To(Succeed())
			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			services, err = httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(BeEmpty())
		})

		It("updates the reverse proxy service when the route moves to a private gateway", func() {
			nn := setup("http-route-transition")
			defer cleanup(nn)

			createRoute(nn, GatewayClassNamePublic)

			_, err := httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			markResourceReady(nn)

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			services, err := httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(HaveLen(1))
			Expect(*services[0].Private).To(BeFalse())

			// Move the route to the private gateway.
			hr := &gwv1.HTTPRoute{}
			Expect(k8sClient.Get(ctx, nn, hr)).To(Succeed())
			hr.Spec.ParentRefs = []gwv1.ParentReference{
				{Name: gwv1.ObjectName(GatewayClassNamePrivate)},
			}
			Expect(k8sClient.Update(ctx, hr)).To(Succeed())

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			// The service is updated in place rather than deleted.
			services, err = httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(HaveLen(1))
			Expect(*services[0].Private).To(BeTrue())
		})

		It("deletes the reverse proxy service when the route is deleted", func() {
			nn := setup("http-route-delete")
			defer cleanup(nn)

			createRoute(nn, GatewayClassNamePublic)

			_, err := httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			markResourceReady(nn)

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			services, err := httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(HaveLen(1))

			hr := &gwv1.HTTPRoute{}
			Expect(k8sClient.Get(ctx, nn, hr)).To(Succeed())
			Expect(k8sClient.Delete(ctx, hr)).To(Succeed())

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			services, err = httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(BeEmpty())
		})

		It("keeps both services when one route moves to a private gateway", func() {
			nn := setup("http-route-shared")
			secondNN := client.ObjectKey{Name: "test-resource-2", Namespace: nn.Namespace}
			defer cleanup(nn)

			createRoute(nn, GatewayClassNamePublic)
			createRoute(secondNN, GatewayClassNamePublic)

			_, err := httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: secondNN})
			Expect(err).NotTo(HaveOccurred())

			markResourceReady(nn)

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: secondNN})
			Expect(err).NotTo(HaveOccurred())

			hr := &gwv1.HTTPRoute{}
			Expect(k8sClient.Get(ctx, nn, hr)).To(Succeed())
			secondHR := &gwv1.HTTPRoute{}
			Expect(k8sClient.Get(ctx, secondNN, secondHR)).To(Succeed())

			// Each route owns its own service on the shared hostname.
			services, err := httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(HaveLen(2))
			Expect([]string{services[0].Name, services[1].Name}).To(ConsistOf(
				proxyServiceName("test.example.com", string(hr.UID)),
				proxyServiceName("test.example.com", string(secondHR.UID)),
			))

			// Moving the second route to the private gateway updates its
			// service in place; the first route keeps its public service.
			secondHR.Spec.ParentRefs = []gwv1.ParentReference{
				{Name: gwv1.ObjectName(GatewayClassNamePrivate)},
			}
			Expect(k8sClient.Update(ctx, secondHR)).To(Succeed())

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: secondNN})
			Expect(err).NotTo(HaveOccurred())

			services, err = httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(HaveLen(2))
			privates := make([]bool, 0, len(services))
			for _, svc := range services {
				privates = append(privates, *svc.Private)
			}
			Expect(privates).To(ConsistOf(true, false))
		})

		It("sets access groups from the backend service annotation for private gateways", func() {
			nn := setup("http-route-access-groups")
			defer cleanup(nn)

			group, err := httpRouteRec.Netbird.Groups.Create(ctx, api.GroupRequest{Name: "ops"})
			Expect(err).NotTo(HaveOccurred())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: nn.Namespace, Name: "backend"}, svc)).To(Succeed())
			svc.Annotations = map[string]string{serviceGroupsAnnotation: "ops"}
			Expect(k8sClient.Update(ctx, svc)).To(Succeed())

			createRoute(nn, GatewayClassNamePrivate)

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			markResourceReady(nn)

			_, err = httpRouteRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			services, err := httpRouteRec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(services).To(HaveLen(1))
			Expect(*services[0].Private).To(BeTrue())
			Expect(services[0].AccessGroups).ToNot(BeNil())
			Expect(*services[0].AccessGroups).To(ConsistOf(group.Id))
		})
	})
})

func ptr[T any](v T) *T {
	return &v
}
