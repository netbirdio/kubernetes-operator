// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

var _ = Describe("NetworkRouter Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var netRouterRec *NetworkRouterReconciler
		var setupKeyRec *SetupKeyReconciler
		var groupRec *GroupReconciler

		var nn client.ObjectKey

		BeforeEach(func() {
			// envtest runs no namespace controller, so a deleted namespace never goes
			// away and each spec needs its own.
			nn = client.ObjectKey{
				Name:      "test-resource",
				Namespace: "network-router-" + rand.String(5),
			}
			nbClient := netbirdmock.Client()
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

		It("creates a routing peer along with a deployment", func() {
			zoneReq := api.ZoneRequest{
				Name:   "cluster.local",
				Domain: "cluster.local",
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
						Name: "cluster.local",
					},
				},
			}
			Expect(k8sClient.Create(ctx, netRouter)).To(Succeed())

			group := &nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("networkrouter-%s", netRouter.Name),
					Namespace: nn.Namespace,
				},
			}
			setupKey := &nbv1alpha1.SetupKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("networkrouter-%s", netRouter.Name),
					Namespace: nn.Namespace,
				},
			}
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("networkrouter-%s", netRouter.Name),
					Namespace: nn.Namespace,
				},
			}

			for range 3 {
				_, err := netRouterRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				Expect(err).NotTo(HaveOccurred())

				_, err = groupRec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(group)})
				Expect(err).NotTo(HaveOccurred())

				_, err = setupKeyRec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(setupKey)})
				Expect(err).NotTo(HaveOccurred())
			}

			err = k8sClient.Get(ctx, nn, netRouter)
			Expect(err).NotTo(HaveOccurred())
			Expect(netRouter.Status.NetworkID).ToNot(BeEmpty())
			_, err = netRouterRec.Netbird.Networks.Routers(netRouter.Status.NetworkID).Get(ctx, netRouter.Status.RoutingPeerID)
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(group), group)
			Expect(err).NotTo(HaveOccurred())
			Expect(group.OwnerReferences[0].UID).To(Equal(netRouter.UID))

			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(setupKey), setupKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(setupKey.OwnerReferences[0].UID).To(Equal(netRouter.UID))

			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(dep), dep)
			Expect(err).NotTo(HaveOccurred())
			Expect(dep.OwnerReferences[0].UID).To(Equal(netRouter.UID))
			nbContainer := dep.Spec.Template.Spec.Containers[0]
			Expect(nbContainer.Name).To(Equal("netbird"))
			Expect(nbContainer.LivenessProbe).NotTo(BeNil())
			Expect(nbContainer.LivenessProbe.Exec.Command).To(Equal([]string{"netbird", "status", "--check", "ready"}))
			Expect(nbContainer.LivenessProbe.FailureThreshold).To(BeEquivalentTo(6))

			routingPeerResp, err := netRouterRec.Netbird.Networks.Routers(netRouter.Status.NetworkID).Get(ctx, netRouter.Status.RoutingPeerID)
			Expect(err).NotTo(HaveOccurred())
			Expect((*routingPeerResp.PeerGroups)[0]).To(Equal(group.Status.GroupID))
		})

		It("is ready only while every routing peer is ready", func() {
			zoneReq := api.ZoneRequest{
				Name:   "cluster.local",
				Domain: "cluster.local",
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
						Name: "cluster.local",
					},
				},
			}
			Expect(k8sClient.Create(ctx, netRouter)).To(Succeed())
			group := client.ObjectKey{Name: fmt.Sprintf("networkrouter-%s", netRouter.Name), Namespace: nn.Namespace}
			reconcileAll := func() {
				_, err := netRouterRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				Expect(err).NotTo(HaveOccurred())
				_, err = groupRec.Reconcile(ctx, reconcile.Request{NamespacedName: group})
				Expect(err).NotTo(HaveOccurred())
				_, err = setupKeyRec.Reconcile(ctx, reconcile.Request{NamespacedName: group})
				Expect(err).NotTo(HaveOccurred())
			}
			ready := func() metav1.ConditionStatus {
				Expect(k8sClient.Get(ctx, nn, netRouter)).To(Succeed())
				cond := meta.FindStatusCondition(netRouter.Status.Conditions, nbv1alpha1.ReadyCondition)
				Expect(cond).NotTo(BeNil())
				return cond.Status
			}
			setReadyReplicas := func(n int32) {
				dep := &appsv1.Deployment{}
				Expect(k8sClient.Get(ctx, group, dep)).To(Succeed())
				dep.Status.ObservedGeneration = dep.Generation
				dep.Status.Replicas = 3
				dep.Status.UpdatedReplicas = 3
				dep.Status.ReadyReplicas = n
				Expect(k8sClient.Status().Update(ctx, dep)).To(Succeed())
				_, err := netRouterRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				Expect(err).NotTo(HaveOccurred())
			}

			// The Deployment controller does not run here, so the Deployment's status
			// stays empty: the state right after the operator first applies it.
			for range 3 {
				reconcileAll()
			}
			Expect(ready()).To(Equal(metav1.ConditionFalse))

			setReadyReplicas(2)
			Expect(ready()).To(Equal(metav1.ConditionFalse))

			setReadyReplicas(3)
			Expect(ready()).To(Equal(metav1.ConditionTrue))

			setReadyReplicas(1)
			Expect(ready()).To(Equal(metav1.ConditionFalse))
		})
	})
})
