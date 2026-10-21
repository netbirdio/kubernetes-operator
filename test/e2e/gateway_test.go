// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
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

	// routeTimeout is how long a route may take to be served once its Gateway is
	// programmed. The operator only has to create a network resource by then.
	routeTimeout = time.Minute
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

	host := proxyHost("web")
	route := httpRoute(ns, "web", gw.Name, host, svc.Name, backendServicePort)
	require.NoError(t, e.k8s.Create(t.Context(), route))

	res := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: ns}}
	e.waitReady(t, res)
	assert.EqualT(t, router.Name, res.Spec.NetworkRouterRef.Name, "the resource goes through the Gateway's router")

	serviceID := requireProxyServices(t, e, host, 1, res.Status.ResourceID)
	requireProxyAnswers(t, proxy, host, svc.Name+"-")

	// Reconciling the route again must update its proxy service in place. Each
	// look is a single listing, so a service deleted and recreated in between
	// shows up as a missing service or a new ID instead of being waited out.
	e.touch(t, route)
	for range 5 {
		time.Sleep(2 * time.Second)
		services, err := proxyServicesFor(t.Context(), e, host)
		require.NoError(t, err)
		require.Len(t, services, 1, "proxy services for %s after the route was reconciled again", host)
		assert.EqualT(t, serviceID, services[0].Id, "reconciling the route again replaced its proxy service")
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
// in the Gateway's network that a peer reaches over raw TCP, and that deleting
// the route removes it.
func TestTCPRoute(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	fx := e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "tcproute")

	router := e.createRouter(t, ns, 1)
	gw := e.createGateway(t, ns, "private", privateGatewayClass, router.Name)
	svc := e.createBackend(t, ns, "web")

	route := tcpRoute(ns, "web", gw.Name, svc.Name, backendServicePort)
	require.NoError(t, e.k8s.Create(t.Context(), route))

	res := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: ns}}
	e.waitReady(t, res)
	nbRes, err := e.nb.Networks.Resources(router.Status.NetworkID).Get(t.Context(), res.Status.ResourceID)
	require.NoError(t, err)
	assert.EqualT(t, svc.Spec.ClusterIP, resourceAddr(nbRes.Address), "the resource is the Service's ClusterIP")

	removePolicy := e.allowClientsToResource(t, fx, res.Status.ResourceID)
	requireTCPAnswers(t, fx.laptop, resourceFQDN(svc.Name, ns), backendServicePort, svc.Name+"-")
	removePolicy()

	resourceID := res.Status.ResourceID
	require.NoError(t, e.k8s.Delete(t.Context(), route))
	e.waitGone(t, route)
	e.waitGone(t, res)
	requireGone(t, "network resource", resourceID, e.nb.Networks.Resources(router.Status.NetworkID).Get)
}

// TestRoutesAppliedWithGateway applies a router, its Gateways and their routes
// together, the way one kubectl apply or a GitOps sync does. A Gateway is only
// programmed once its router's peers are ready, so the routes reach the operator
// before their Gateways are programmed, and have to be served soon after they
// are. Getting the Gateways programmed is not what is under test, so it gets the
// usual timeout; the routes then get routeTimeout.
func TestRoutesAppliedWithGateway(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	fx := e.requireNetworkFixtures(t)
	proxy := e.requireProxy(t)
	ns := e.createNamespace(t, "routes-applied")

	web := e.createBackend(t, ns, "web")
	tcp := e.createBackend(t, ns, "tcp")

	router := e.startRouter(t, ns, 1)
	public := gatewayFor(ns, "public", publicGatewayClass, router.Name)
	private := gatewayFor(ns, "private", privateGatewayClass, router.Name)
	host := proxyHost("web")
	for _, obj := range []client.Object{
		public,
		private,
		httpRoute(ns, "web", public.Name, host, web.Name, backendServicePort),
		tcpRoute(ns, "tcp", private.Name, tcp.Name, backendServicePort),
	} {
		require.NoError(t, e.k8s.Create(t.Context(), obj))
	}
	e.waitProgrammed(t, public)
	e.waitProgrammed(t, private)

	t.Run("HTTPRoute", func(t *testing.T) {
		t.Parallel()
		res := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: web.Name, Namespace: ns}}
		e.waitReadyWithin(t, res, routeTimeout)
		requireProxyServices(t, e, host, 1, res.Status.ResourceID)
		requireProxyAnswers(t, proxy, host, web.Name+"-")
	})
	t.Run("TCPRoute", func(t *testing.T) {
		t.Parallel()
		res := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: tcp.Name, Namespace: ns}}
		e.waitReadyWithin(t, res, routeTimeout)
		e.allowClientsToResource(t, fx, res.Status.ResourceID)
		requireTCPAnswers(t, fx.laptop, resourceFQDN(tcp.Name, ns), backendServicePort, tcp.Name+"-")
	})
}

// TestHTTPRouteBackendPort publishes a Service that listens on a port other than
// 80. The proxy service has to target the port the HTTPRoute's backendRef names,
// or the proxy reaches nothing.
func TestHTTPRouteBackendPort(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	e.requireNetworkFixtures(t)
	proxy := e.requireProxy(t)
	ns := e.createNamespace(t, "backend-port")

	router := e.createRouter(t, ns, 1)
	gw := e.createGateway(t, ns, "public", publicGatewayClass, router.Name)
	svc := e.createBackendOnPort(t, ns, "web", backendPort)

	host := proxyHost("web")
	require.NoError(t, e.k8s.Create(t.Context(), httpRoute(ns, "web", gw.Name, host, svc.Name, backendPort)))

	res := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: ns}}
	e.waitReady(t, res)
	requireProxyServices(t, e, host, 1, res.Status.ResourceID)
	services, err := proxyServicesFor(t.Context(), e, host)
	require.NoError(t, err)
	require.Len(t, services, 1, "proxy services for %s", host)
	// No request can reach the Service through a target on another port, so a
	// wrong port fails here rather than after the traffic check times out.
	require.EqualT(t, backendPort, services[0].Targets[0].Port, "the proxy target's port is the one the backendRef names")
	requireProxyAnswers(t, proxy, host, svc.Name+"-")
}

// allowClientsToResource creates a policy that lets the clients group reach the
// network resource itself, which is how a user grants access to a resource a
// route created in no group. The returned func deletes the policy, which has to
// go before the resource can; it also runs when the test ends.
func (e *environment) allowClientsToResource(t *testing.T, fx *networkFixtures, resourceID string) func() {
	t.Helper()
	name := "e2e-clients-to-" + resourceID
	policy, err := e.nb.Policies.Create(t.Context(), api.PostApiPoliciesJSONRequestBody{
		Name:    name,
		Enabled: true,
		Rules: []api.PolicyRuleUpdate{
			{
				Name:                name,
				Enabled:             true,
				Action:              api.PolicyRuleUpdateActionAccept,
				Protocol:            api.PolicyRuleUpdateProtocolAll,
				Sources:             &[]string{fx.clientsGroupID},
				DestinationResource: &api.Resource{Id: resourceID, Type: api.ResourceTypeHost},
			},
		},
	})
	require.NoError(t, err)
	var once sync.Once
	remove := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := e.nb.Policies.Delete(ctx, *policy.Id); err != nil {
				t.Errorf("delete policy %s: %v", name, err)
			}
		})
	}
	t.Cleanup(remove)
	return remove
}

// requireTCPAnswers waits until nc, run on the peer, gets an answer naming the
// backend over a raw TCP connection to host:port. The request it writes is
// plain HTTP because that is what the backend speaks.
func requireTCPAnswers(t *testing.T, peer *harness.Client, host string, port int32, want string) {
	t.Helper()
	script := fmt.Sprintf(`printf 'GET /hostname HTTP/1.0\r\n\r\n' | nc -w 5 %s %d`, host, port)
	require.Eventually(t, func(ctx context.Context) error {
		code, out, err := peer.Exec(ctx, "sh", "-c", script)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("nc %s %d from %s failed (exit %d): %s", host, port, peer.Hostname(), code, out)
		}
		if !strings.Contains(out, want) {
			return fmt.Errorf("nc %s %d answered %q, want a response naming %q", host, port, out, want)
		}
		return nil
	}, reachTimeout, 3*time.Second)
}

// resourceFQDN is the DNS name the operator gives a Service's network resource
// in the fixture zone.
func resourceFQDN(service, namespace string) string {
	return fmt.Sprintf("%s.%s.%s", service, namespace, dnsZone)
}

// proxyHost returns a unique hostname on the proxy cluster's domain.
func proxyHost(prefix string) string {
	return fmt.Sprintf("%s-%s.%s", prefix, rand.String(6), harness.AgentNetworkCluster)
}

// httpRoute builds an HTTPRoute that serves host from the Service's port
// through the Gateway.
func httpRoute(namespace, name, gateway, host, service string, port gwv1.PortNumber) *gwv1.HTTPRoute {
	return &gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: gwv1.HTTPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{
				ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(gateway)}},
			},
			Hostnames: []gwv1.Hostname{gwv1.Hostname(host)},
			Rules: []gwv1.HTTPRouteRule{
				{
					BackendRefs: []gwv1.HTTPBackendRef{
						{BackendRef: gwv1.BackendRef{BackendObjectReference: gwv1.BackendObjectReference{
							Name: gwv1.ObjectName(service),
							Port: new(port),
						}}},
					},
				},
			},
		},
	}
}

// tcpRoute builds a TCPRoute that exposes the Service's port through the
// Gateway.
func tcpRoute(namespace, name, gateway, service string, port gwv1.PortNumber) *gwv1alpha2.TCPRoute {
	return &gwv1alpha2.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: gwv1alpha2.TCPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{
				ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(gateway)}},
			},
			Rules: []gwv1alpha2.TCPRouteRule{
				{
					BackendRefs: []gwv1.BackendRef{
						{BackendObjectReference: gwv1.BackendObjectReference{
							Name: gwv1.ObjectName(service),
							Port: new(port),
						}},
					},
				},
			},
		},
	}
}

// gatewayFor builds a Gateway of the class whose single listener names the
// NetworkRouter.
func gatewayFor(namespace, name, class, router string) *gwv1.Gateway {
	return &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: gwv1.GatewaySpec{
			GatewayClassName: gwv1.ObjectName(class),
			Listeners: []gwv1.Listener{
				{Name: gwv1.SectionName(router), Protocol: "gateway.netbird.io/NetworkRouter", Port: 1},
			},
		},
	}
}

// createGateway creates a Gateway of the class whose single listener names the
// NetworkRouter, and waits until it is programmed.
func (e *environment) createGateway(t *testing.T, namespace, name, class, router string) *gwv1.Gateway {
	t.Helper()
	gw := gatewayFor(namespace, name, class, router)
	require.NoError(t, e.k8s.Create(t.Context(), gw))
	e.waitProgrammed(t, gw)
	return gw
}

// waitProgrammed waits until the Gateway is programmed.
func (e *environment) waitProgrammed(t *testing.T, gw *gwv1.Gateway) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(gw), gw); err != nil {
			return err
		}
		if !meta.IsStatusConditionTrue(gw.Status.Conditions, string(gwv1.GatewayConditionProgrammed)) {
			return fmt.Errorf("gateway %s is not programmed: %v", gw.Name, gw.Status.Conditions)
		}
		return nil
	}, readyTimeout, 2*time.Second)
}

// requireProxyServices waits until the server holds exactly want proxy services
// for the domain, and when it holds one, that it targets the resource. It
// returns that service's ID.
func requireProxyServices(t *testing.T, e *environment, domain string, want int, resourceID string) string {
	t.Helper()
	var id string
	require.Eventually(t, func(ctx context.Context) error {
		matching, err := proxyServicesFor(ctx, e, domain)
		if err != nil {
			return err
		}
		if len(matching) != want {
			return fmt.Errorf("%d proxy services for %s, want %d", len(matching), domain, want)
		}
		if want != 1 {
			return nil
		}
		if len(matching[0].Targets) != 1 || matching[0].Targets[0].TargetId != resourceID {
			return fmt.Errorf("the proxy service for %s targets %+v, want the resource %s", domain, matching[0].Targets, resourceID)
		}
		id = matching[0].Id
		return nil
	}, readyTimeout, 2*time.Second)
	return id
}

// proxyServicesFor lists the proxy services the server holds for the domain.
func proxyServicesFor(ctx context.Context, e *environment, domain string) ([]api.Service, error) {
	services, err := e.nb.ReverseProxyServices.List(ctx)
	if err != nil {
		return nil, err
	}
	var matching []api.Service
	for _, s := range services {
		if s.Domain == domain {
			matching = append(matching, s)
		}
	}
	return matching, nil
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
