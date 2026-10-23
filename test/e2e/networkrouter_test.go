// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
)

// TestNetworkRouter covers a NetworkRouter's whole lifecycle against the
// server: the network, router, group and setup key it creates, the routing
// peers that join with that key, and that deleting it removes all of them.
func TestNetworkRouter(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "router")

	router := e.createRouter(t, ns, 3)
	require.NotEmpty(t, router.Status.NetworkID, "status.networkID")
	require.NotEmpty(t, router.Status.RoutingPeerID, "status.routingPeerID")

	dep := &appsv1.Deployment{}
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "networkrouter-" + router.Name}, dep))
	assert.EqualT(t, int32(3), dep.Status.ReadyReplicas, "Ready must mean every routing peer is ready")

	group := &nbv1alpha1.Group{}
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "networkrouter-" + router.Name}, group))
	require.NotEmpty(t, group.Status.GroupID, "the router's group has no NetBird ID")
	setupKey := &nbv1alpha1.SetupKey{}
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "networkrouter-" + router.Name}, setupKey))
	require.NotEmpty(t, setupKey.Status.SetupKeyID, "the router's setup key has no NetBird ID")

	network, err := e.nb.Networks.Get(t.Context(), router.Status.NetworkID)
	require.NoError(t, err)
	assert.EqualT(t, router.Name, network.Name, "network name")

	nbRouter, err := e.nb.Networks.Routers(router.Status.NetworkID).Get(t.Context(), router.Status.RoutingPeerID)
	require.NoError(t, err)
	assert.TrueT(t, nbRouter.Enabled, "router enabled")
	assert.TrueT(t, nbRouter.Masquerade, "router masquerades")
	require.NotNil(t, nbRouter.PeerGroups, "router peer groups")
	assert.Equal(t, []string{group.Status.GroupID}, *nbRouter.PeerGroups, "the router routes through the router's own group")

	key, err := e.nb.SetupKeys.Get(t.Context(), setupKey.Status.SetupKeyID)
	require.NoError(t, err)
	assert.TrueT(t, key.Ephemeral, "routing peers join with an ephemeral key")
	assert.Equal(t, []string{group.Status.GroupID}, key.AutoGroups, "routing peers join the router's group")

	// Every replica joins as its own peer, in the router's group and connected.
	require.Eventually(t, func(ctx context.Context) error {
		peers, err := e.peersInGroup(ctx, group.Status.GroupID)
		if err != nil {
			return err
		}
		connected := 0
		for _, peer := range peers {
			if peer.Connected {
				connected++
			}
		}
		if connected != 3 {
			return fmt.Errorf("%d of 3 routing peers connected", connected)
		}
		return nil
	}, 3*time.Minute, 2*time.Second)

	require.NoError(t, e.k8s.Delete(t.Context(), router))
	e.waitGone(t, router)
	requireGone(t, "network", router.Status.NetworkID, e.nb.Networks.Get)
	requireGone(t, "group", group.Status.GroupID, e.nb.Groups.Get)
	requireGone(t, "setup key", setupKey.Status.SetupKeyID, e.nb.SetupKeys.Get)
}

// peersInGroup returns the peers in a NetBird group.
func (e *environment) peersInGroup(ctx context.Context, groupID string) ([]peerState, error) {
	group, err := e.nb.Groups.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}
	peers := make([]peerState, 0, len(group.Peers))
	for _, member := range group.Peers {
		peer, err := e.nb.Peers.Get(ctx, member.Id)
		if err != nil {
			return nil, err
		}
		peers = append(peers, peerState{ID: peer.Id, Name: peer.Name, Connected: peer.Connected})
	}
	return peers, nil
}

type peerState struct {
	ID        string
	Name      string
	Connected bool
}

// requireGone waits until the server answers not found for an object, which is
// the only answer that proves a delete. Any other error means the check itself
// failed and is reported as such rather than read as success.
func requireGone[T any](t *testing.T, kind, id string, get func(context.Context, string) (T, error)) {
	t.Helper()
	require.NotEmpty(t, id, "no %s ID was recorded, so its deletion cannot be checked", kind)
	require.Eventually(t, func(ctx context.Context) error {
		_, err := get(ctx, id)
		if err == nil {
			return fmt.Errorf("%s %s still exists on the server", kind, id)
		}
		if netbird.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("check that %s %s is gone: %w", kind, id, err)
	}, 3*time.Minute, 2*time.Second)
}
