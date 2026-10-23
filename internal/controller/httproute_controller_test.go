// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
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
		const hostname = "web.example.com"

		var rec *HTTPRouteReconciler
		var route client.ObjectKey

		BeforeEach(func() {
			rec = &HTTPRouteReconciler{
				Client:  k8sClient,
				Netbird: netbirdmock.Client(),
			}

			// envtest runs no namespace controller, so a deleted namespace never goes
			// away and each spec needs its own.
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "httproute-" + rand.String(5)}}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())
			route = client.ObjectKey{Namespace: ns.Name, Name: "web"}

			gwc := &gwv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "netbird-" + rand.String(5)},
				Spec:       gwv1.GatewayClassSpec{ControllerName: GatewayControllerName},
			}
			Expect(k8sClient.Create(ctx, gwc)).To(Succeed())
			netRouter := &nbv1alpha1.NetworkRouter{
				ObjectMeta: metav1.ObjectMeta{Name: "router", Namespace: ns.Name},
				Spec: nbv1alpha1.NetworkRouterSpec{
					DNSZoneRef: nbv1alpha1.DNSZoneReference{Name: "example.com"},
				},
			}
			Expect(k8sClient.Create(ctx, netRouter)).To(Succeed())
			gw := &gwv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: ns.Name},
				Spec: gwv1.GatewaySpec{
					GatewayClassName: gwv1.ObjectName(gwc.Name),
					Listeners: []gwv1.Listener{
						{Name: gwv1.SectionName(netRouter.Name), Protocol: "gateway.netbird.io/NetworkRouter", Port: 1},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
				Type:   string(gwv1.GatewayConditionProgrammed),
				Status: metav1.ConditionTrue,
				Reason: string(gwv1.GatewayReasonProgrammed),
			})
			Expect(k8sClient.Status().Update(ctx, gw)).To(Succeed())

			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns.Name},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{Name: "http", Port: 80}},
				},
			}
			Expect(k8sClient.Create(ctx, svc)).To(Succeed())
			hr := &gwv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: route.Name, Namespace: route.Namespace},
				Spec: gwv1.HTTPRouteSpec{
					CommonRouteSpec: gwv1.CommonRouteSpec{
						ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(gw.Name)}},
					},
					Hostnames: []gwv1.Hostname{hostname},
					Rules: []gwv1.HTTPRouteRule{
						{
							BackendRefs: []gwv1.HTTPBackendRef{
								{BackendRef: gwv1.BackendRef{BackendObjectReference: gwv1.BackendObjectReference{
									Name: gwv1.ObjectName(svc.Name),
									Port: new(gwv1.PortNumber(80)),
								}}},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, hr)).To(Succeed())

			// The first pass creates the NetworkResource for the backend and waits
			// for it. Its own controller does not run here, so mark it ready.
			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: route})
			Expect(err).NotTo(HaveOccurred())
			netResource := &nbv1alpha1.NetworkResource{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns.Name, Name: svc.Name}, netResource)).To(Succeed())
			netResource.Status.ResourceID = "resource-1"
			meta.SetStatusCondition(&netResource.Status.Conditions, metav1.Condition{
				Type:   nbv1alpha1.ReadyCondition,
				Status: metav1.ConditionTrue,
				Reason: nbv1alpha1.ReconciledReason,
			})
			Expect(k8sClient.Status().Update(ctx, netResource)).To(Succeed())
		})

		proxyServices := func() []api.Service {
			services, err := rec.Netbird.ReverseProxyServices.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			return services
		}

		It("keeps one proxy service per hostname across reconciles", func() {
			for range 3 {
				_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: route})
				Expect(err).NotTo(HaveOccurred())
			}

			services := proxyServices()
			Expect(services).To(HaveLen(1))
			Expect(services[0].Domain).To(Equal(hostname))
			Expect(services[0].Targets).To(HaveLen(1))
			Expect(services[0].Targets[0].TargetId).To(Equal("resource-1"))
		})

		It("removes duplicate proxy services for a hostname", func() {
			for range 3 {
				_, err := rec.Netbird.ReverseProxyServices.Create(ctx, api.ServiceRequest{Domain: hostname, Name: hostname})
				Expect(err).NotTo(HaveOccurred())
			}

			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: route})
			Expect(err).NotTo(HaveOccurred())

			services := proxyServices()
			Expect(services).To(HaveLen(1))
			Expect(services[0].Targets).To(HaveLen(1))
			Expect(services[0].Targets[0].TargetId).To(Equal("resource-1"))
		})
	})
})
