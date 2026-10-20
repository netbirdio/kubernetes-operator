// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	egressPort = 8080
	// egressReply is what the outside peer answers on egressPort.
	egressReply = "egress-reached-laptop"
)

// TestNetworkEgress lets a workload in the cluster reach a NetBird peer outside
// it through a NetworkEgress: pod, egress Service, the forwarder in the routing
// peer pods, the routing peer, NetBird, and the outside peer, which answers
// HTTP on egressPort.
func TestNetworkEgress(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	fx := e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "egress")

	router := e.createRouter(t, ns, 1)
	group := &nbv1alpha1.Group{}
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "networkrouter-" + router.Name}, group))
	laptopIP := e.peerIP(t, laptopName)
	serveHTTP(t, fx.laptop, egressPort, egressReply)

	// The only policy in the fixtures lets the outside peer in, not the routing
	// peers out, so allow this router's peers to reach the outside peer.
	policy, err := e.nb.Policies.Create(t.Context(), api.PostApiPoliciesJSONRequestBody{
		Name:    "e2e-egress-" + router.Name,
		Enabled: true,
		Rules: []api.PolicyRuleUpdate{
			{
				Name:         "e2e-egress-" + router.Name,
				Enabled:      true,
				Action:       api.PolicyRuleUpdateActionAccept,
				Protocol:     api.PolicyRuleUpdateProtocolTcp,
				Ports:        &[]string{fmt.Sprint(egressPort)},
				Sources:      &[]string{group.Status.GroupID},
				Destinations: &[]string{fx.clientsGroupID},
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := e.nb.Policies.Delete(context.Background(), *policy.Id); err != nil {
			t.Logf("delete policy %s: %v", policy.Name, err)
		}
	})

	egress := &nbv1alpha1.NetworkEgress{
		ObjectMeta: metav1.ObjectMeta{Name: laptopName, Namespace: ns},
		Spec: nbv1alpha1.NetworkEgressSpec{
			NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{Name: router.Name, Namespace: ns},
			Target: nbv1alpha1.NetworkEgressTarget{
				IP: &nbv1alpha1.NetworkEgressIPTarget{Address: laptopIP},
			},
			Ports: []nbv1alpha1.NetworkEgressPort{{Name: "http", Port: egressPort}},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), egress))
	e.waitReady(t, egress)

	svc := &corev1.Service{}
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKeyFromObject(egress), svc))
	require.Len(t, svc.Spec.Ports, 1, "egress Service ports")
	assert.EqualT(t, int32(egressPort), svc.Spec.Ports[0].Port, "egress Service port")
	e.requireEgressEndpoints(t, ns, svc.Name)

	url := fmt.Sprintf("http://%s.%s.svc:%d/", svc.Name, ns, egressPort)
	require.NoError(t, e.runCheck(t.Context(), ns, "egress-client",
		fmt.Sprintf("wget -q -O - -T 5 %s | grep -q %s", url, egressReply)))

	require.NoError(t, e.k8s.Delete(t.Context(), egress))
	e.waitGone(t, egress)
	e.waitGone(t, svc)
}

// requireEgressEndpoints waits until the egress Service's EndpointSlices point
// at the router's ready pods, which is where the operator's forwarder listens.
func (e *environment) requireEgressEndpoints(t *testing.T, namespace, service string) {
	t.Helper()
	require.NoError(t, eventually(t.Context(), readyTimeout, func(ctx context.Context) error {
		slicesList := &discoveryv1.EndpointSliceList{}
		if err := e.k8s.List(ctx, slicesList, client.InNamespace(namespace), client.MatchingLabels{discoveryv1.LabelServiceName: service}); err != nil {
			return err
		}
		for _, s := range slicesList.Items {
			if slices.ContainsFunc(s.Endpoints, func(ep discoveryv1.Endpoint) bool {
				return len(ep.Addresses) > 0 && ep.Conditions.Ready != nil && *ep.Conditions.Ready
			}) && len(s.Ports) > 0 {
				return nil
			}
		}
		return fmt.Errorf("no EndpointSlice of %s has a ready endpoint", service)
	}))
}

// peerIP returns the NetBird IP of the peer registered under the hostname.
func (e *environment) peerIP(t *testing.T, hostname string) string {
	t.Helper()
	peers, err := e.nb.Peers.List(t.Context())
	require.NoError(t, err)
	idx := slices.IndexFunc(peers, func(p api.Peer) bool { return p.Hostname == hostname })
	require.NotEqual(t, -1, idx, "no peer registered as %s", hostname)
	return peers[idx].Ip
}

// serveHTTP answers every connection to port on the peer with a 200 and the
// body, using the BusyBox nc in the client image. It runs until the peer's
// container is removed.
func serveHTTP(t *testing.T, peer *harness.Client, port int, body string) {
	t.Helper()
	script := fmt.Sprintf(`printf '#!/bin/sh\nprintf "HTTP/1.0 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s"\n' > /tmp/respond-%d.sh`,
		len(body), body, port)
	start := fmt.Sprintf(`%s && chmod +x /tmp/respond-%d.sh && setsid nc -lk -p %d -e /tmp/respond-%d.sh >/dev/null 2>&1 &`,
		script, port, port, port)
	code, out, err := peer.Exec(t.Context(), "sh", "-c", start)
	require.NoError(t, err)
	require.Zero(t, code, "start the HTTP responder on %s: %s", peer.Hostname(), out)

	local := fmt.Sprintf("http://127.0.0.1:%d/", port)
	require.NoError(t, eventually(t.Context(), reachTimeout, func(ctx context.Context) error {
		got, err := httpGet(ctx, peer, local)
		if err != nil {
			return err
		}
		if got != body {
			return fmt.Errorf("the responder on %s answered %q, want %q", peer.Hostname(), got, body)
		}
		return nil
	}))
}
