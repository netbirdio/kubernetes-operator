// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	publicGatewayClass  = "netbird-public"
	privateGatewayClass = "netbird-private"
)

// TestHTTPRoute publishes a Service through an HTTPRoute and requests it the
// way the public would: through the NetBird reverse proxy, which reaches the
// Service over NetBird through the Gateway's routing peer. A second reconcile
// must not add a proxy service, and deleting the route must take both the proxy
// service and the network resource with it.
func TestHTTPRoute(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	e.requireNetworkFixtures(t)
	proxy := e.requireProxy(t)
	ns := e.createNamespace(t, "httproute")

	router := e.createRouter(t, ns, 1)
	gw := e.createGateway(t, ns, "public", publicGatewayClass, router.Name)
	svc := e.createBackend(t, ns, "web")

	host := fmt.Sprintf("web-%s.%s", rand.String(6), harness.AgentNetworkCluster)
	route := &gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
		Spec: gwv1.HTTPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{
				ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(gw.Name)}},
			},
			Hostnames: []gwv1.Hostname{gwv1.Hostname(host)},
			Rules: []gwv1.HTTPRouteRule{
				{
					BackendRefs: []gwv1.HTTPBackendRef{
						{BackendRef: gwv1.BackendRef{BackendObjectReference: gwv1.BackendObjectReference{
							Name: gwv1.ObjectName(svc.Name),
							Port: new(gwv1.PortNumber(backendServicePort)),
						}}},
					},
				},
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), route))

	res := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: ns}}
	e.waitReady(t, res)
	assert.EqualT(t, router.Name, res.Spec.NetworkRouterRef.Name, "the resource goes through the Gateway's router")

	requireProxyServices(t, e, host, 1, res.Status.ResourceID)
	requireProxyAnswers(t, proxy, host, svc.Name+"-")

	// Reconciling the route again must update its proxy service in place.
	e.touch(t, route)
	for range 5 {
		time.Sleep(2 * time.Second)
		requireProxyServices(t, e, host, 1, res.Status.ResourceID)
	}

	require.NoError(t, e.k8s.Delete(t.Context(), route))
	e.waitGone(t, route)
	requireProxyServices(t, e, host, 0, "")
	e.waitGone(t, res)
	require.Eventually(t, func(ctx context.Context) error {
		status, _, err := proxy.HTTPSGet(ctx, host, "/hostname", nil)
		if err == nil && status == http.StatusOK {
			return fmt.Errorf("https://%s still serves the deleted route", host)
		}
		return nil
	}, reachTimeout, 3*time.Second)
}

// TestTCPRoute checks that a TCPRoute exposes its backend as a network resource
// in the Gateway's network, and that deleting the route removes it.
func TestTCPRoute(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "tcproute")

	router := e.createRouter(t, ns, 1)
	gw := e.createGateway(t, ns, "private", privateGatewayClass, router.Name)
	svc := e.createBackend(t, ns, "web")

	route := &gwv1alpha2.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
		Spec: gwv1alpha2.TCPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{
				ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(gw.Name)}},
			},
			Rules: []gwv1alpha2.TCPRouteRule{
				{
					BackendRefs: []gwv1.BackendRef{
						{BackendObjectReference: gwv1.BackendObjectReference{
							Name: gwv1.ObjectName(svc.Name),
							Port: new(gwv1.PortNumber(backendServicePort)),
						}},
					},
				},
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), route))

	res := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: ns}}
	e.waitReady(t, res)
	nbRes, err := e.nb.Networks.Resources(router.Status.NetworkID).Get(t.Context(), res.Status.ResourceID)
	require.NoError(t, err)
	assert.EqualT(t, svc.Spec.ClusterIP, resourceAddr(nbRes.Address), "the resource is the Service's ClusterIP")

	resourceID := res.Status.ResourceID
	require.NoError(t, e.k8s.Delete(t.Context(), route))
	e.waitGone(t, route)
	e.waitGone(t, res)
	requireGone(t, "network resource", resourceID, e.nb.Networks.Resources(router.Status.NetworkID).Get)
}

// createGateway creates a Gateway of the class whose single listener names the
// NetworkRouter, and waits until it is programmed.
func (e *environment) createGateway(t *testing.T, namespace, name, class, router string) *gwv1.Gateway {
	t.Helper()
	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: gwv1.GatewaySpec{
			GatewayClassName: gwv1.ObjectName(class),
			Listeners: []gwv1.Listener{
				{Name: gwv1.SectionName(router), Protocol: "gateway.netbird.io/NetworkRouter", Port: 1},
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), gw))
	require.Eventually(t, func(ctx context.Context) error {
		if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(gw), gw); err != nil {
			return err
		}
		if !meta.IsStatusConditionTrue(gw.Status.Conditions, string(gwv1.GatewayConditionProgrammed)) {
			return fmt.Errorf("gateway %s is not programmed: %v", name, gw.Status.Conditions)
		}
		return nil
	}, readyTimeout, 2*time.Second)
	return gw
}

// requireProxyServices waits until the server holds exactly want proxy services
// for the domain, and when it holds one, that it targets the resource.
func requireProxyServices(t *testing.T, e *environment, domain string, want int, resourceID string) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		services, err := e.nb.ReverseProxyServices.List(ctx)
		if err != nil {
			return err
		}
		var matching []api.Service
		for _, s := range services {
			if s.Domain == domain {
				matching = append(matching, s)
			}
		}
		if len(matching) != want {
			return fmt.Errorf("%d proxy services for %s, want %d", len(matching), domain, want)
		}
		if want == 1 && (len(matching[0].Targets) != 1 || matching[0].Targets[0].TargetId != resourceID) {
			return fmt.Errorf("the proxy service for %s targets %+v, want the resource %s", domain, matching[0].Targets, resourceID)
		}
		return nil
	}, readyTimeout, 2*time.Second)
}

// requireProxyAnswers waits until the reverse proxy serves the domain with a
// body that starts with want.
func requireProxyAnswers(t *testing.T, proxy *harness.Proxy, domain, want string) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		status, body, err := proxy.HTTPSGet(ctx, domain, "/hostname", nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK || !strings.HasPrefix(body, want) {
			return fmt.Errorf("https://%s/hostname answered %d %q, want 200 starting with %q", domain, status, body, want)
		}
		return nil
	}, reachTimeout, 3*time.Second)
}
