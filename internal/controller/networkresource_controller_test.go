// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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

		var nn client.ObjectKey

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

			// Envtest never finishes deleting a namespace, so every spec gets its own.
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "network-resource-",
				},
			}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())
			nn = client.ObjectKey{
				Name:      "test-resource",
				Namespace: ns.Name,
			}
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

		createNetworkRouterWithZone := func(zoneName, zoneDomain string) *nbv1alpha1.NetworkRouter {
			zoneReq := api.ZoneRequest{
				Name:   zoneName,
				Domain: zoneDomain,
			}
			_, err := netRouterRec.Netbird.DNSZones.CreateZone(ctx, zoneReq)
			Expect(err).ToNot(HaveOccurred())

			netRouter := &nbv1alpha1.NetworkRouter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.NetworkRouterSpec{
					DNSZoneRef: nbv1alpha1.DNSZoneReference{
						Name: zoneName,
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
			return netRouter
		}

		createNetworkRouter := func() *nbv1alpha1.NetworkRouter {
			return createNetworkRouterWithZone("cluster.local", "cluster.local")
		}

		createService := func(spec corev1.ServiceSpec) *corev1.Service {
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: nn.Namespace,
				},
				Spec: spec,
			}
			Expect(k8sClient.Create(ctx, svc)).To(Succeed())
			return svc
		}

		reconcileNetworkResource := func(netRouter *nbv1alpha1.NetworkRouter, svc *corev1.Service) *nbv1alpha1.NetworkResource {
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
			_, err := netResourceRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, nn, netResource)).To(Succeed())
			return netResource
		}

		expectExposed := func(netResource *nbv1alpha1.NetworkResource, svc *corev1.Service) {
			Expect(meta.IsStatusConditionTrue(netResource.Status.Conditions, nbv1alpha1.ReadyCondition)).To(BeTrue())
			Expect(netResource.Status.NetworkID).NotTo(BeEmpty())
			Expect(netResource.Status.ResourceID).NotTo(BeEmpty())
			Expect(netResource.Status.DNSZoneID).NotTo(BeEmpty())
			Expect(netResource.Status.DNSRecordID).NotTo(BeEmpty())

			resource, err := netResourceRec.Netbird.Networks.Resources(netResource.Status.NetworkID).Get(ctx, netResource.Status.ResourceID)
			Expect(err).NotTo(HaveOccurred())
			Expect(resource.Address).To(Equal(svc.Spec.ClusterIP))

			record, err := netResourceRec.Netbird.DNSZones.GetRecord(ctx, netResource.Status.DNSZoneID, netResource.Status.DNSRecordID)
			Expect(err).NotTo(HaveOccurred())
			Expect(record.Content).To(Equal(svc.Spec.ClusterIP))
		}

		expectRejected := func(netResource *nbv1alpha1.NetworkResource, message string) {
			cond := meta.FindStatusCondition(netResource.Status.Conditions, nbv1alpha1.ReadyCondition)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Message).To(Equal(message))
			Expect(netResource.Status.ResourceID).To(BeEmpty())
			Expect(netResource.Status.DNSRecordID).To(BeEmpty())
		}

		It("creates a network resource and DNS record", func() {
			netRouter := createNetworkRouter()
			svc := createService(corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{
						Port: 8080,
					},
				},
			})

			netResource := reconcileNetworkResource(netRouter, svc)
			expectExposed(netResource, svc)
		})

		It("names the DNS record after the zone domain, not the zone name", func() {
			// The API allows a zone whose name differs from its domain, and records must
			// live under the domain or the management server rejects them.
			netRouter := createNetworkRouterWithZone("internal-services", "svc.example.com")
			svc := createService(corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{
						Port: 8080,
					},
				},
			})

			netResource := reconcileNetworkResource(netRouter, svc)
			expectExposed(netResource, svc)

			record, err := netResourceRec.Netbird.DNSZones.GetRecord(ctx, netResource.Status.DNSZoneID, netResource.Status.DNSRecordID)
			Expect(err).NotTo(HaveOccurred())
			Expect(record.Name).To(Equal(fmt.Sprintf("%s.%s.svc.example.com", svc.Name, svc.Namespace)), "record should be named under the zone domain")
		})

		It("creates a network resource for a LoadBalancer Service", func() {
			netRouter := createNetworkRouter()
			// The API server allocates the ClusterIP even without a cloud provider.
			svc := createService(corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
					{
						Port: 8080,
					},
				},
			})
			Expect(svc.Spec.ClusterIP).NotTo(BeEmpty())

			netResource := reconcileNetworkResource(netRouter, svc)
			expectExposed(netResource, svc)
		})

		It("creates a network resource for a NodePort Service", func() {
			netRouter := createNetworkRouter()
			svc := createService(corev1.ServiceSpec{
				Type: corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{
					{
						Port: 8080,
					},
				},
			})
			Expect(svc.Spec.ClusterIP).NotTo(BeEmpty())

			netResource := reconcileNetworkResource(netRouter, svc)
			expectExposed(netResource, svc)
		})

		It("rejects an ExternalName Service", func() {
			netRouter := createNetworkRouter()
			svc := createService(corev1.ServiceSpec{
				Type:         corev1.ServiceTypeExternalName,
				ExternalName: "example.com",
			})

			netResource := reconcileNetworkResource(netRouter, svc)
			expectRejected(netResource, "Referenced Service is of type ExternalName and has no ClusterIP.")
		})

		It("rejects a headless Service", func() {
			netRouter := createNetworkRouter()
			svc := createService(corev1.ServiceSpec{
				ClusterIP: corev1.ClusterIPNone,
				Ports: []corev1.ServicePort{
					{
						Port: 8080,
					},
				},
			})

			netResource := reconcileNetworkResource(netRouter, svc)
			expectRejected(netResource, "Referenced Service does not have a ClusterIP set.")
		})
	})
})
