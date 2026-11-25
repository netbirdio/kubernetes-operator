// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
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

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
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
		var nbRecorder *netbirdmock.Recorder

		var nn client.ObjectKey

		BeforeEach(func() {
			// envtest runs no namespace controller, so a deleted namespace never goes
			// away and each spec needs its own.
			nn = client.ObjectKey{
				Name:      "test-resource",
				Namespace: "network-router-" + rand.String(5),
			}
			var nbClient *netbird.Client
			nbClient, nbRecorder = netbirdmock.RecordingClient()
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

		createReadyNetworkRouter := func() *nbv1alpha1.NetworkRouter {
			_, err := netRouterRec.Netbird.DNSZones.CreateZone(ctx, api.ZoneRequest{
				Name:   "cluster.local",
				Domain: "cluster.local",
			})
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
			key := client.ObjectKey{Name: fmt.Sprintf("networkrouter-%s", netRouter.Name), Namespace: nn.Namespace}
			for range 3 {
				_, err := netRouterRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				Expect(err).NotTo(HaveOccurred())
				_, err = groupRec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
				Expect(err).NotTo(HaveOccurred())
				_, err = setupKeyRec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(k8sClient.Get(ctx, nn, netRouter)).To(Succeed())
			Expect(netRouter.Status.NetworkID).NotTo(BeEmpty())
			Expect(netRouter.Status.RoutingPeerID).NotTo(BeEmpty())
			return netRouter
		}

		It("does not write the network or router when nothing changed", func() {
			createReadyNetworkRouter()

			// Every write shows up in the account's activity log, so the periodic resync
			// must leave unchanged objects alone.
			nbRecorder.Reset()
			_, err := netRouterRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			writes := map[string]int{}
			for _, pattern := range []string{
				"PUT /api/networks/{id}",
				"PUT /api/networks/{network}/routers/{id}",
				"POST /api/networks",
				"POST /api/networks/{network}/routers",
			} {
				writes[pattern] = nbRecorder.Count(pattern)
			}
			Expect(writes).To(HaveEach(0), "unchanged network and router should not be written")
		})

		It("restores the network and router when they drift", func() {
			netRouter := createReadyNetworkRouter()
			networkID := netRouter.Status.NetworkID
			routerID := netRouter.Status.RoutingPeerID

			// Simulate edits made in the dashboard.
			_, err := netRouterRec.Netbird.Networks.Update(ctx, networkID, api.NetworkRequest{Name: "renamed"})
			Expect(err).NotTo(HaveOccurred())
			_, err = netRouterRec.Netbird.Networks.Routers(networkID).Update(ctx, routerID, api.NetworkRouterRequest{
				Enabled:    false,
				Masquerade: true,
				Metric:     1,
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = netRouterRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			network, err := netRouterRec.Netbird.Networks.Get(ctx, networkID)
			Expect(err).NotTo(HaveOccurred())
			Expect(network.Name).To(Equal(netRouter.Name), "network name should be restored")

			router, err := netRouterRec.Netbird.Networks.Routers(networkID).Get(ctx, routerID)
			Expect(err).NotTo(HaveOccurred())
			Expect(router.Enabled).To(BeTrue(), "router should be re-enabled")
			Expect(router.Metric).To(Equal(9999), "router metric should be restored")
			Expect(router.PeerGroups).NotTo(BeNil(), "router peer groups should be restored")
			Expect(*router.PeerGroups).To(HaveLen(1), "router peer groups should be restored")
		})
	})
})

func TestNetworkMatches(t *testing.T) {
	t.Parallel()

	req := api.NetworkRequest{Name: "router"}
	tests := []struct {
		name    string
		network api.Network
		want    bool
	}{
		{name: "same settings", network: api.Network{Name: "router"}, want: true},
		{name: "empty description", network: api.Network{Name: "router", Description: new("")}, want: true},
		{name: "different name", network: api.Network{Name: "renamed"}, want: false},
		{name: "different description", network: api.Network{Name: "router", Description: new("edited")}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, networkMatches(&tt.network, req))
		})
	}
}

func TestNetworkRouterMatches(t *testing.T) {
	t.Parallel()

	req := api.NetworkRouterRequest{
		Enabled:    true,
		Masquerade: true,
		Metric:     9999,
		PeerGroups: new([]string{"group-a", "group-b"}),
	}
	// router returns the router the request would create, changed by modify.
	router := func(modify func(*api.NetworkRouter)) *api.NetworkRouter {
		r := &api.NetworkRouter{
			Enabled:    req.Enabled,
			Masquerade: req.Masquerade,
			Metric:     req.Metric,
			PeerGroups: new([]string{"group-a", "group-b"}),
		}
		modify(r)
		return r
	}
	tests := []struct {
		name   string
		modify func(*api.NetworkRouter)
		want   bool
	}{
		{name: "same settings", modify: func(r *api.NetworkRouter) {}, want: true},
		{name: "empty peer", modify: func(r *api.NetworkRouter) { r.Peer = new("") }, want: true},
		{name: "peer groups in another order", modify: func(r *api.NetworkRouter) { r.PeerGroups = new([]string{"group-b", "group-a"}) }, want: true},
		{name: "disabled", modify: func(r *api.NetworkRouter) { r.Enabled = false }, want: false},
		{name: "masquerade off", modify: func(r *api.NetworkRouter) { r.Masquerade = false }, want: false},
		{name: "different metric", modify: func(r *api.NetworkRouter) { r.Metric = 1 }, want: false},
		{name: "peer set", modify: func(r *api.NetworkRouter) { r.Peer = new("peer-1") }, want: false},
		{name: "different peer groups", modify: func(r *api.NetworkRouter) { r.PeerGroups = new([]string{"group-a", "group-c"}) }, want: false},
		{name: "missing peer groups", modify: func(r *api.NetworkRouter) { r.PeerGroups = nil }, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, networkRouterMatches(router(tt.modify), req))
		})
	}
}
