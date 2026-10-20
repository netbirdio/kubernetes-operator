// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	reachTimeout        = 3 * time.Minute
	unreachableFailures = 3
)

// TestNetworkResource exposes a Service through a NetworkRouter and checks it
// the way a user would see it: a peer outside the cluster reaches the Service by
// its DNS name through the routing peer, only while the resource is in a group
// a policy lets the peer reach, and not at all once the resource is deleted.
func TestNetworkResource(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	fx := e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "resource")

	router := e.createRouter(t, ns, "router", 1)
	svc := e.createBackend(t, ns, "web")

	res := &nbv1alpha1.NetworkResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: ns,
		},
		Spec: nbv1alpha1.NetworkResourceSpec{
			NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{Name: router.Name, Namespace: ns},
			ServiceRef:       corev1.LocalObjectReference{Name: svc.Name},
			Groups:           []nbv1alpha1.GroupReference{{Name: new(resourcesGroup)}},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), res))
	e.waitReady(t, res)
	resourceID := res.Status.ResourceID
	assert.EqualT(t, router.Status.NetworkID, res.Status.NetworkID, "the resource is in the router's network")
	assert.EqualT(t, fx.zoneID, res.Status.DNSZoneID, "the record is in the router's zone")

	resources := e.nb.Networks.Resources(res.Status.NetworkID)
	nbRes, err := resources.Get(t.Context(), resourceID)
	require.NoError(t, err)
	assert.TrueT(t, nbRes.Enabled, "resource enabled")
	assert.EqualT(t, svc.Spec.ClusterIP, resourceAddr(nbRes.Address), "the resource is the Service's ClusterIP")
	assert.Equal(t, []string{fx.resourcesGroupID}, groupIDs(nbRes.Groups), "resource groups")

	record, err := e.nb.DNSZones.GetRecord(t.Context(), res.Status.DNSZoneID, res.Status.DNSRecordID)
	require.NoError(t, err)
	fqdn := fmt.Sprintf("%s.%s.%s", svc.Name, ns, dnsZone)
	assert.EqualT(t, fqdn, record.Name, "record name")
	assert.EqualT(t, api.DNSRecordTypeA, record.Type, "record type")
	assert.EqualT(t, svc.Spec.ClusterIP, record.Content, "the record points at the ClusterIP")

	url := fmt.Sprintf("http://%s:%d/hostname", fqdn, backendPort)
	requireReachable(t, fx.laptop, url, svc.Name+"-")

	// Moving the resource out of the group the policy covers has to cut the peer
	// off, and moving it back has to restore access, without the resource being
	// recreated either way.
	e.setResourceGroups(t, res, "All")
	requireUnreachable(t, fx.laptop, url)
	assert.EqualT(t, resourceID, res.Status.ResourceID, "moving the resource out of the group recreated it")
	e.setResourceGroups(t, res, resourcesGroup)
	requireReachable(t, fx.laptop, url, svc.Name+"-")
	assert.EqualT(t, resourceID, res.Status.ResourceID, "moving the resource back into the group recreated it")

	require.NoError(t, e.k8s.Delete(t.Context(), res))
	e.waitGone(t, res)
	requireGone(t, "network resource", resourceID, resources.Get)
	requireGone(t, "DNS record", res.Status.DNSRecordID, func(ctx context.Context, id string) (*api.DNSRecord, error) {
		return e.nb.DNSZones.GetRecord(ctx, res.Status.DNSZoneID, id)
	})
	requireUnreachable(t, fx.laptop, url)
}

// setResourceGroups replaces a NetworkResource's groups and waits until the
// operator has applied the change.
func (e *environment) setResourceGroups(t *testing.T, res *nbv1alpha1.NetworkResource, groups ...string) {
	t.Helper()
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKeyFromObject(res), res))
	refs := make([]nbv1alpha1.GroupReference, 0, len(groups))
	for _, g := range groups {
		refs = append(refs, nbv1alpha1.GroupReference{Name: new(g)})
	}
	res.Spec.Groups = refs
	require.NoError(t, e.k8s.Update(t.Context(), res))
	e.waitReady(t, res)
}

// requireReachable waits until a GET from the peer succeeds with a body that
// starts with want.
func requireReachable(t *testing.T, peer *harness.Client, url, want string) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		body, err := httpGet(ctx, peer, url)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(body, want) {
			return fmt.Errorf("GET %s answered %q, want a body starting with %q", url, body, want)
		}
		return nil
	}, reachTimeout, 3*time.Second)
}

// requireUnreachable waits until GETs from the peer fail unreachableFailures
// times in a row, so a single dropped request cannot pass for access that was
// never cut.
func requireUnreachable(t *testing.T, peer *harness.Client, url string) {
	t.Helper()
	failures := 0
	require.Eventually(t, func(ctx context.Context) error {
		body, err := httpGet(ctx, peer, url)
		if err == nil {
			failures = 0
			return fmt.Errorf("GET %s still answers: %q", url, body)
		}
		failures++
		if failures < unreachableFailures {
			return fmt.Errorf("GET %s failed %d of %d times in a row: %w", url, failures, unreachableFailures, err)
		}
		return nil
	}, reachTimeout, 3*time.Second)
}

// resourceAddr strips the host prefix length the server stores an address
// with.
func resourceAddr(address string) string {
	if prefix, err := netip.ParsePrefix(address); err == nil {
		return prefix.Addr().String()
	}
	return address
}

func groupIDs(groups []api.GroupMinimum) []string {
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.Id)
	}
	return ids
}
