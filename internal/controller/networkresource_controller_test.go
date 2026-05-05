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

	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

var _ = Describe("NetworkResource Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var netResourceRec *NetworkResourceReconciler
		var netRouterRec *NetworkRouterReconciler
		var setupKeyRec *SetupKeyReconciler
		var groupRec *GroupReconciler

		nn := client.ObjectKey{
			Name:      "test-resource",
			Namespace: "network-resource",
		}

		BeforeEach(func() {
			nbClient := netbirdmock.Client()
			netResourceRec = &NetworkResourceReconciler{
				Client:  k8sClient,
				Netbird: nbClient,
			}
			netRouterRec = &NetworkRouterReconciler{
				Client:        k8sClient,
				Netbird:       nbClient,
				ClientImage:   "docker.io/netbirdio/netbird:latest",
				ManagementURL: "https://netbird.io",
			}
			setupKeyRec = &SetupKeyReconciler{
				Client:  k8sClient,
				Netbird: nbClient,
			}
			groupRec = &GroupReconciler{
				Client:  k8sClient,
				Netbird: nbClient,
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

		It("creates a network resource and DNS record", func() {
			zoneReq := api.ZoneRequest{
				Name:   "cluster.local",
				Domain: "cluster.local",
			}
			_, err := netRouterRec.Netbird.DNSZones.CreateZone(ctx, zoneReq)
			Expect(err).ToNot(HaveOccurred())

			// Create network router that we reference.
			netRouter := &nbv1alpha1.NetworkRouter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.NetworkRouterSpec{
					DNSZoneRef: nbv1alpha1.DNSZoneReference{
						Name: "cluster.local",
					},
				},
			}
			Expect(k8sClient.Create(ctx, netRouter)).To(Succeed())
			for range 3 {
				_, err := netRouterRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				Expect(err).NotTo(HaveOccurred())
				key := client.ObjectKey{Name: fmt.Sprintf("networkrouter-%s", netRouter.Name), Namespace: nn.Namespace}
				_, err = groupRec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
				Expect(err).NotTo(HaveOccurred())
				_, err = setupKeyRec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
				Expect(err).NotTo(HaveOccurred())
			}

			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: nn.Namespace,
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Port: 8080,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, svc)).To(Succeed())

			netResource := &nbv1alpha1.NetworkResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.NetworkResourceSpec{
					NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{
						Name:      netRouter.Name,
						Namespace: netRouter.Namespace,
					},
					ServiceRef: corev1.LocalObjectReference{
						Name: svc.Name,
					},
				},
			}
			Expect(k8sClient.Create(ctx, netResource)).To(Succeed())
			_, err = netResourceRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, nn, netResource)
			Expect(err).NotTo(HaveOccurred())
			Expect(netResource.Status.NetworkID).NotTo(BeEmpty())
			Expect(netResource.Status.ResourceID).NotTo(BeEmpty())
			Expect(netResource.Status.DNSZoneID).NotTo(BeEmpty())
			Expect(netResource.Status.DNSRecordID).NotTo(BeEmpty())
		})
	})
})
