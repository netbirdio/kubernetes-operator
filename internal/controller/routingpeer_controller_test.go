package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

var _ = Describe("RoutingPeer Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var routingPeerRec *RoutingPeerReconciler
		var setupKeyRec *SetupKeyReconciler
		var groupRec *GroupReconciler

		nn := client.ObjectKey{
			Name:      "test-resource",
			Namespace: "routing-peer",
		}

		BeforeEach(func() {
			nbClient := netbirdmock.Client()
			routingPeerRec = &RoutingPeerReconciler{
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
			networkReq := api.NetworkRequest{
				Name: "test",
			}
			networkResp, err := routingPeerRec.Netbird.Networks.Create(ctx, networkReq)
			Expect(err).ToNot(HaveOccurred())

			routingPeer := &nbv1alpha1.RoutingPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.RoutingPeerSpec{
					NetworkRef: nbv1alpha1.ResourceReference{
						ID: &networkResp.Id,
					},
				},
			}
			Expect(k8sClient.Create(ctx, routingPeer)).To(Succeed())

			group := &nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("routingpeer-%s", routingPeer.Name),
					Namespace: nn.Namespace,
				},
			}
			setupKey := &nbv1alpha1.SetupKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("routingpeer-%s", routingPeer.Name),
					Namespace: nn.Namespace,
				},
			}
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("routingpeer-%s", routingPeer.Name),
					Namespace: nn.Namespace,
				},
			}

			for range 3 {
				_, err = routingPeerRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				Expect(err).NotTo(HaveOccurred())

				_, err = groupRec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(group)})
				Expect(err).NotTo(HaveOccurred())

				_, err = setupKeyRec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(setupKey)})
				Expect(err).NotTo(HaveOccurred())
			}

			err = k8sClient.Get(ctx, nn, routingPeer)
			Expect(err).NotTo(HaveOccurred())
			Expect(*routingPeer.Status.RoutingPeerID).NotTo(BeEmpty())
			Expect(*routingPeer.Status.NetworkID).To(Equal(networkResp.Id))
			_, err = routingPeerRec.Netbird.Networks.Routers(*routingPeer.Status.NetworkID).Get(ctx, *routingPeer.Status.RoutingPeerID)
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(group), group)
			Expect(err).NotTo(HaveOccurred())
			Expect(group.OwnerReferences[0].UID).To(Equal(routingPeer.UID))

			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(setupKey), setupKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(setupKey.OwnerReferences[0].UID).To(Equal(routingPeer.UID))

			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(dep), dep)
			Expect(err).NotTo(HaveOccurred())
			Expect(dep.OwnerReferences[0].UID).To(Equal(routingPeer.UID))

			routingPeerResp, err := routingPeerRec.Netbird.Networks.Routers(*routingPeer.Status.NetworkID).Get(ctx, *routingPeer.Status.RoutingPeerID)
			Expect(err).NotTo(HaveOccurred())
			Expect((*routingPeerResp.PeerGroups)[0]).To(Equal(*group.Status.GroupID))
		})
	})
})
