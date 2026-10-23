// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"log"
	"slices"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

// upgradeFixtures are objects the published operator created before the
// upgrade to the operator under test, and the NetBird IDs it gave them.
type upgradeFixtures struct {
	group    client.ObjectKey
	router   client.ObjectKey
	resource client.ObjectKey

	groupID       string
	networkID     string
	routingPeerID string
	resourceID    string
	dnsRecordID   string

	url, want string
}

// createUpgradeFixtures has the published operator expose a Service and create
// a group, and confirms the Service is reachable, before the upgrade replaces
// that operator.
func (e *environment) createUpgradeFixtures(ctx context.Context) (_ *upgradeFixtures, err error) {
	e.networkOnce.Do(func() {
		e.network, e.networkErr = e.createNetworkFixtures(ctx)
	})
	if e.networkErr != nil {
		return nil, fmt.Errorf("network fixtures: %w", e.networkErr)
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "upgrade-"}}
	if err := e.k8s.Create(ctx, ns); err != nil {
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		dctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		log.Printf("e2e: namespace %s:\n%s", ns.Name, e.describeNamespace(dctx, ns.Name))
	}()
	group := &nbv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: ns.Name},
		Spec:       nbv1alpha1.GroupSpec{Name: "e2e-upgrade-" + rand.String(6)},
	}
	if err := e.k8s.Create(ctx, group); err != nil {
		return nil, err
	}
	if err := e.waitReadyCtx(ctx, group); err != nil {
		return nil, err
	}
	router, err := e.newRouter(ctx, ns.Name, 1)
	if err != nil {
		return nil, err
	}
	svc, err := e.newBackend(ctx, ns.Name, "web")
	if err != nil {
		return nil, err
	}
	res := &nbv1alpha1.NetworkResource{
		ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: ns.Name},
		Spec: nbv1alpha1.NetworkResourceSpec{
			NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{Name: router.Name, Namespace: ns.Name},
			ServiceRef:       corev1.LocalObjectReference{Name: svc.Name},
			Groups:           []nbv1alpha1.GroupReference{{Name: new(resourcesGroup)}},
		},
	}
	if err := e.k8s.Create(ctx, res); err != nil {
		return nil, err
	}
	if err := e.waitReadyCtx(ctx, res); err != nil {
		return nil, err
	}

	fx := &upgradeFixtures{
		group:    client.ObjectKeyFromObject(group),
		router:   client.ObjectKeyFromObject(router),
		resource: client.ObjectKeyFromObject(res),

		url:  fmt.Sprintf("http://%s.%s.%s/hostname", svc.Name, ns.Name, dnsZone),
		want: svc.Name + "-",
	}
	if err := waitReachable(ctx, e.network.laptop, fx.url, fx.want); err != nil {
		return nil, fmt.Errorf("the published operator's resource is not reachable: %w", err)
	}

	// Read the IDs last: the published operator may still have been settling
	// them until the traffic flowed.
	if err := e.k8s.Get(ctx, fx.group, group); err != nil {
		return nil, err
	}
	if err := e.k8s.Get(ctx, fx.router, router); err != nil {
		return nil, err
	}
	if err := e.k8s.Get(ctx, fx.resource, res); err != nil {
		return nil, err
	}
	fx.groupID = group.Status.GroupID
	fx.networkID = router.Status.NetworkID
	fx.routingPeerID = router.Status.RoutingPeerID
	fx.resourceID = res.Status.ResourceID
	fx.dnsRecordID = res.Status.DNSRecordID
	return fx, nil
}

// TestUpgrade checks what the published operator created once the operator
// under test has taken over: every object ready again, every NetBird object
// kept rather than recreated, and the Service still reachable.
func TestUpgrade(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	if e.upgrade == nil {
		t.Skipf("%s is set, so the run started on the local chart and there was no upgrade", envSkipUpgrade)
	}
	fx := e.requireNetworkFixtures(t)
	u := e.upgrade

	// Only the operator under test deploys the client this run built. Until the
	// router's pods run it, the statuses below can still be the published
	// operator's, and the ID checks would compare that operator with itself.
	e.requireRoutingPeersOn(t, u.router, e.clientImage)

	group := &nbv1alpha1.Group{ObjectMeta: metav1.ObjectMeta{Name: u.group.Name, Namespace: u.group.Namespace}}
	e.waitReady(t, group)
	assert.EqualT(t, u.groupID, group.Status.GroupID, "the upgrade recreated the group")

	router := &nbv1alpha1.NetworkRouter{ObjectMeta: metav1.ObjectMeta{Name: u.router.Name, Namespace: u.router.Namespace}}
	e.waitReady(t, router)
	assert.EqualT(t, u.networkID, router.Status.NetworkID, "the upgrade recreated the network")
	assert.EqualT(t, u.routingPeerID, router.Status.RoutingPeerID, "the upgrade recreated the router")

	res := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: u.resource.Name, Namespace: u.resource.Namespace}}
	e.waitReady(t, res)
	assert.EqualT(t, u.resourceID, res.Status.ResourceID, "the upgrade recreated the network resource")
	assert.EqualT(t, u.dnsRecordID, res.Status.DNSRecordID, "the upgrade recreated the DNS record")

	requireReachable(t, fx.laptop, u.url, u.want)
}

// requireRoutingPeersOn waits until every routing peer pod of the router runs
// the client image and is ready, with none of an older template left.
func (e *environment) requireRoutingPeersOn(t *testing.T, router client.ObjectKey, image string) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		pods := &corev1.PodList{}
		if err := e.k8s.List(ctx, pods, client.InNamespace(router.Namespace), client.MatchingLabels{
			"app.kubernetes.io/name":     "networkrouter",
			"app.kubernetes.io/instance": router.Name,
		}); err != nil {
			return err
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("router %s has no routing peer pods", router)
		}
		for _, pod := range pods.Items {
			if pod.DeletionTimestamp != nil {
				return fmt.Errorf("routing peer pod %s is still terminating", pod.Name)
			}
			idx := slices.IndexFunc(pod.Spec.Containers, func(c corev1.Container) bool { return c.Name == "netbird" })
			if idx == -1 || pod.Spec.Containers[idx].Image != image {
				return fmt.Errorf("routing peer pod %s does not run %s yet", pod.Name, image)
			}
			if !podReady(pod) {
				return fmt.Errorf("routing peer pod %s is not ready", pod.Name)
			}
		}
		return nil
	}, readyTimeout, 2*time.Second)
}

func podReady(pod corev1.Pod) bool {
	return slices.ContainsFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue
	})
}
