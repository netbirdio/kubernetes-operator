// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

var _ = Describe("NetworkEgress Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var netEgressRec *NetworkEgressReconciler
		var forwarderRec *ForwarderServiceReconciler

		nn := client.ObjectKey{
			Name:      "test-resource",
			Namespace: "network-egress",
		}
		BeforeEach(func() {
			netEgressRec = &NetworkEgressReconciler{
				Client: k8sClient,
			}
			forwarderRec = &ForwarderServiceReconciler{
				Client: k8sClient,
			}

			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: nn.Namespace,
				},
			}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		})

		AfterEach(func() {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: nn.Namespace,
				},
			}
			err := k8sClient.Get(ctx, client.ObjectKeyFromObject(ns), ns)
			if kerrors.IsNotFound(err) {
				return
			}
			Expect(err).ToNot(HaveOccurred())
			Expect(k8sClient.Delete(ctx, ns)).To(Succeed())
		})

		It("creates a egress service with endpoint slices", func() {
			netRouter := &nbv1alpha1.NetworkRouter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "egress-router",
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.NetworkRouterSpec{
					DNSZoneRef: nbv1alpha1.DNSZoneReference{
						Name: "foo.bar",
					},
				},
			}
			Expect(k8sClient.Create(ctx, netRouter)).To(Succeed())

			netEgress := &nbv1alpha1.NetworkEgress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.NetworkEgressSpec{
					NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{
						Name:      netRouter.Name,
						Namespace: nn.Namespace,
					},
					Target: nbv1alpha1.NetworkEgressTarget{
						FQDN: &nbv1alpha1.NetworkEgressFQDNTarget{
							Hostname: "example.com",
						},
					},
					Ports: []nbv1alpha1.NetworkEgressPort{
						{
							Name: "http",
							Port: 80,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, netEgress)).To(Succeed())
			_, err := netEgressRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			egressSvc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
			}
			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(egressSvc), egressSvc)
			Expect(err).NotTo(HaveOccurred())
			Expect(egressSvc.Labels[EgressRouterNameLabel]).To(Equal(netRouter.Name))
			Expect(egressSvc.Labels[EgressRouterNamespaceLabel]).To(Equal(netRouter.Namespace))
			Expect(egressSvc.Spec.Ports).To(HaveLen(1))
			Expect(egressSvc.Spec.Ports[0].TargetPort.String()).To(Equal("80"))

			_, err = forwarderRec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: fmt.Sprintf("networkrouter-%s-forwarder", netRouter.Name), Namespace: nn.Namespace}})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
