// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"testing"

	"github.com/go-openapi/testify/v2/require"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestPathPrefixFor(t *testing.T) {
	t.Parallel()

	prefix := gwv1.PathMatchPathPrefix
	regex := gwv1.PathMatchRegularExpression
	val := "/push/"

	withMatch := gwv1.HTTPRouteRule{Matches: []gwv1.HTTPRouteMatch{
		{Path: &gwv1.HTTPPathMatch{Type: &prefix, Value: &val}},
	}}
	require.Equal(t, "/push/", derefStr(pathPrefixFor(withMatch)))

	// no matches -> catch-all (nil)
	require.Nil(t, pathPrefixFor(gwv1.HTTPRouteRule{}))

	// regex matches are not prefixes -> nil
	rx := "/x.*"
	regexRule := gwv1.HTTPRouteRule{Matches: []gwv1.HTTPRouteMatch{
		{Path: &gwv1.HTTPPathMatch{Type: &regex, Value: &rx}},
	}}
	require.Nil(t, pathPrefixFor(regexRule))
}

func TestProxyServiceUpToDate(t *testing.T) {
	t.Parallel()

	reqMode := api.ServiceRequestModeHttp
	svcMode := api.ServiceMode("http")
	target := func() api.ServiceTarget {
		return api.ServiceTarget{
			Enabled:    true,
			Port:       80,
			Protocol:   api.ServiceTargetProtocolHttp,
			TargetType: api.ServiceTargetTargetTypeHost,
			TargetId:   "res-1",
		}
	}

	req := api.ServiceRequest{
		Domain:           "search.ccbash.de",
		Enabled:          true,
		Name:             "search.ccbash.de",
		Mode:             &reqMode,
		PassHostHeader:   new(false),
		RewriteRedirects: new(false),
		AccessGroups:     &[]string{}, // empty must compare equal to unset
		Targets:          &[]api.ServiceTarget{target()},
	}
	svc := api.Service{
		Domain:           "search.ccbash.de",
		Enabled:          true,
		Name:             "search.ccbash.de",
		Mode:             &svcMode,
		PassHostHeader:   new(false),
		RewriteRedirects: new(false),
		Targets:          []api.ServiceTarget{target()},
	}
	require.True(t, proxyServiceUpToDate(svc, req))

	// differing target port -> not up to date
	t2 := target()
	t2.Port = 8080
	svcDiff := svc
	svcDiff.Targets = []api.ServiceTarget{t2}
	require.False(t, proxyServiceUpToDate(svcDiff, req))

	// adding a crowdsec restriction -> not up to date
	mode := api.AccessRestrictionsCrowdsecModeObserve
	reqCrowdsec := req
	reqCrowdsec.AccessRestrictions = &api.AccessRestrictions{CrowdsecMode: &mode}
	require.False(t, proxyServiceUpToDate(svc, reqCrowdsec))
}

func TestSortTargets(t *testing.T) {
	t.Parallel()

	targets := []api.ServiceTarget{
		{TargetId: "b", Port: 80},
		{TargetId: "a", Port: 90},
		{TargetId: "a", Port: 80},
	}
	sortTargets(targets)
	require.Equal(t, "a", targets[0].TargetId)
	require.Equal(t, 80, targets[0].Port)
	require.Equal(t, "a", targets[1].TargetId)
	require.Equal(t, 90, targets[1].Port)
	require.Equal(t, "b", targets[2].TargetId)
}
