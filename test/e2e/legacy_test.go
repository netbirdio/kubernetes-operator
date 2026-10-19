// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

// The deprecated v1 path: Services exposed through annotations, NBResource,
// NBGroup, NBRoutingPeer and NBPolicy. It is still what existing installs run,
// so it keeps a smoke test until it is removed.

package e2e

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

const (
	legacyExposeAnnotation = "netbird.io/expose"
	legacyGroupsAnnotation = "netbird.io/groups"
	// legacyRouterName is the NBRoutingPeer the operator creates in its own
	// namespace for every exposed Service.
	legacyRouterName = "router"
	legacyCleanup    = "netbird.io/cleanup"
)

// TestLegacyServiceExposure exposes a Service through the netbird.io/expose
// annotation, reaches it from the outside peer by its cluster DNS name, checks
// that the NBGroup the resource owns cannot be deleted from under it, and that
// removing the annotation removes the resource.
func TestLegacyServiceExposure(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	fx := e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "legacy")

	svc := e.createBackend(t, ns, "web")
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKeyFromObject(svc), svc))
	svc.Annotations = map[string]string{
		legacyExposeAnnotation: "true",
		legacyGroupsAnnotation: resourcesGroup,
	}
	require.NoError(t, e.k8s.Update(t.Context(), svc))

	res := &nbv1.NBResource{ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: ns}}
	e.waitLegacyReady(t, res, func() []nbv1.NBCondition { return res.Status.Conditions })
	require.NotNil(t, res.Status.NetworkResourceID, "status.networkResourceID")
	router := &nbv1.NBRoutingPeer{ObjectMeta: metav1.ObjectMeta{Name: legacyRouterName, Namespace: netbirdNamespace}}
	e.waitLegacyReady(t, router, func() []nbv1.NBCondition { return router.Status.Conditions })
	require.NotNil(t, router.Status.NetworkID, "status.networkID")

	resources := e.nb.Networks.Resources(*router.Status.NetworkID)
	nbRes, err := resources.Get(t.Context(), *res.Status.NetworkResourceID)
	require.NoError(t, err)
	fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, ns)
	assert.EqualT(t, fqdn, nbRes.Address, "the resource is the Service's cluster DNS name")
	assert.TrueT(t, slices.Contains(groupIDs(nbRes.Groups), fx.resourcesGroupID), "the resource is in the annotated group")

	requireReachable(t, fx.laptop, fmt.Sprintf("http://%s/hostname", fqdn), svc.Name+"-")

	t.Run("an NBGroup in use cannot be deleted", func(t *testing.T) {
		group := &nbv1.NBGroup{ObjectMeta: metav1.ObjectMeta{Name: resourcesGroup, Namespace: ns}}
		err := e.k8s.Delete(t.Context(), group, client.DryRunAll)
		require.Error(t, err, "deleting the NBGroup a live NBResource owns was allowed")
		assert.Contains(t, err.Error(), "group attached to NBResource", "refused for another reason")
	})

	resourceID := *res.Status.NetworkResourceID
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKeyFromObject(svc), svc))
	delete(svc.Annotations, legacyExposeAnnotation)
	require.NoError(t, e.k8s.Update(t.Context(), svc))
	e.waitGone(t, res)
	requireGone(t, "network resource", resourceID, resources.Get)
}

// TestLegacyPolicyCleanup deletes an NBPolicy whose NetBird policy is already
// gone, which has to finish rather than leave the NBPolicy stuck on its
// finalizer.
func TestLegacyPolicyCleanup(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	e.requireNetworkFixtures(t)

	name := "e2e-policy-" + rand.String(6)
	policy := &nbv1.NBPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			// The chart and NBResource add this finalizer to the NBPolicies they
			// create; the controller never adds it itself.
			Finalizers: []string{legacyCleanup},
		},
		Spec: nbv1.NBPolicySpec{
			Name:              name,
			SourceGroups:      []string{clientsGroup},
			DestinationGroups: []string{resourcesGroup},
			Protocols:         []string{"tcp"},
			Ports:             []int32{80},
			Bidirectional:     true,
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), policy))
	require.NoError(t, eventually(t.Context(), readyTimeout, func(ctx context.Context) error {
		if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
			return err
		}
		if policy.Status.TCPPolicyID == nil {
			return fmt.Errorf("NBPolicy %s has no TCP policy yet", name)
		}
		return nil
	}))
	policyID := *policy.Status.TCPPolicyID
	_, err := e.nb.Policies.Get(t.Context(), policyID)
	require.NoError(t, err)

	require.NoError(t, e.nb.Policies.Delete(t.Context(), policyID))
	require.NoError(t, e.k8s.Delete(t.Context(), policy))
	e.waitGone(t, policy)
}

// waitLegacyReady waits until a v1 object reports Ready, and leaves obj holding
// that state. The v1 types carry their own condition type, without generations.
func (e *environment) waitLegacyReady(t *testing.T, obj client.Object, conditions func() []nbv1.NBCondition) {
	t.Helper()
	require.NoError(t, eventually(t.Context(), readyTimeout, func(ctx context.Context) error {
		if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		idx := slices.IndexFunc(conditions(), func(c nbv1.NBCondition) bool { return c.Type == nbv1.NBSetupKeyReady })
		if idx == -1 {
			return fmt.Errorf("%s has no Ready condition yet", obj.GetName())
		}
		if c := conditions()[idx]; c.Status != corev1.ConditionTrue {
			return fmt.Errorf("%s is not ready: %s: %s", obj.GetName(), c.Reason, c.Message)
		}
		return nil
	}))
}
