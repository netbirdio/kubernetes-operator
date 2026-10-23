// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// The fixtures the network tests share, named rather than identified: IDs are
// assigned by the server, so names are what the tests and the provisioning can
// agree on ahead of time.
const (
	// clientsGroup holds the peer outside the cluster.
	clientsGroup = "e2e-clients"
	// resourcesGroup is the group a network resource has to be in for the
	// clients to reach it. The only policy in the account allows clientsGroup
	// to resourcesGroup.
	resourcesGroup = "e2e-resources"
	// dnsZone is the zone NetworkRouters create records in. Its name and its
	// domain are the same.
	dnsZone = "e2e.internal"
	// laptopName is the hostname of the peer outside the cluster.
	laptopName = "laptop"
	// defaultPolicyName is the allow-all policy a new account starts with.
	defaultPolicyName = "Default"
)

// networkFixtures are the NetBird objects the network tests route through, all
// created through the public API.
type networkFixtures struct {
	clientsGroupID   string
	resourcesGroupID string
	zoneID           string
	// laptop is a NetBird peer outside the cluster, in clientsGroup, standing in
	// for a user's device.
	laptop *harness.Client
}

// requireNetworkFixtures returns the network fixtures, creating them on first
// use.
func (e *environment) requireNetworkFixtures(t *testing.T) *networkFixtures {
	t.Helper()
	e.networkOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		e.network, e.networkErr = e.createNetworkFixtures(ctx)
	})
	if e.networkErr != nil {
		t.Fatalf("network fixtures unavailable: %v", e.networkErr)
	}
	return e.network
}

func (e *environment) createNetworkFixtures(ctx context.Context) (*networkFixtures, error) {
	fx := &networkFixtures{}
	clients, err := e.nb.Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: clientsGroup})
	if err != nil {
		return fx, fmt.Errorf("create group %s: %w", clientsGroup, err)
	}
	fx.clientsGroupID = clients.Id
	resources, err := e.nb.Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: resourcesGroup})
	if err != nil {
		return fx, fmt.Errorf("create group %s: %w", resourcesGroup, err)
	}
	fx.resourcesGroupID = resources.Id

	// With the default allow-all policy in place every peer reaches every
	// resource, and a test could not tell whether the operator put a resource in
	// the right group.
	if err := e.deletePolicy(ctx, defaultPolicyName); err != nil {
		return fx, err
	}
	_, err = e.nb.Policies.Create(ctx, api.PostApiPoliciesJSONRequestBody{
		Name:    "e2e-clients-to-resources",
		Enabled: true,
		Rules: []api.PolicyRuleUpdate{
			{
				Name:          "e2e-clients-to-resources",
				Enabled:       true,
				Action:        api.PolicyRuleUpdateActionAccept,
				Bidirectional: true,
				Protocol:      api.PolicyRuleUpdateProtocolAll,
				Sources:       &[]string{fx.clientsGroupID},
				Destinations:  &[]string{fx.resourcesGroupID},
			},
		},
	})
	if err != nil {
		return fx, fmt.Errorf("create the clients-to-resources policy: %w", err)
	}

	zone, err := e.nb.DNSZones.CreateZone(ctx, api.PostApiDnsZonesJSONRequestBody{
		Name:               dnsZone,
		Domain:             dnsZone,
		DistributionGroups: []string{fx.clientsGroupID},
		Enabled:            new(true),
	})
	if err != nil {
		return fx, fmt.Errorf("create DNS zone %s: %w", dnsZone, err)
	}
	fx.zoneID = zone.Id

	key, err := e.nb.SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-" + laptopName,
		Type:       "reusable",
		ExpiresIn:  int((24 * time.Hour).Seconds()),
		AutoGroups: []string{fx.clientsGroupID},
	})
	if err != nil {
		return fx, fmt.Errorf("create the setup key for %s: %w", laptopName, err)
	}
	fx.laptop, err = harness.StartClient(ctx, e.srv, key.Key, harness.WithClientName(laptopName))
	if err != nil {
		return fx, fmt.Errorf("start the %s peer: %w", laptopName, err)
	}
	if err := fx.laptop.WaitConnected(ctx, 3*time.Minute); err != nil {
		return fx, fmt.Errorf("connect the %s peer: %w\n%s", laptopName, err, tail(fx.laptop.Logs(ctx)))
	}
	return fx, nil
}

func (e *environment) deletePolicy(ctx context.Context, name string) error {
	policies, err := e.nb.Policies.List(ctx)
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}
	for _, p := range policies {
		if p.Name != name || p.Id == nil {
			continue
		}
		if err := e.nb.Policies.Delete(ctx, *p.Id); err != nil {
			return fmt.Errorf("delete policy %s: %w", name, err)
		}
	}
	return nil
}

// httpGet fetches a URL from a peer's network namespace, so the request takes
// whatever route the peer's NetBird client set up, and returns the body.
func httpGet(ctx context.Context, peer *harness.Client, url string) (string, error) {
	code, out, err := peer.Exec(ctx, "wget", "-q", "-O", "-", "-T", "5", url)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("GET %s from %s failed (wget exit %d): %s", url, peer.Hostname(), code, out)
	}
	return out, nil
}
