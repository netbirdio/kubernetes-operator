// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"fmt"
	"strconv"

	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/netbirdio/netbird/shared/management/http/api"

	"github.com/netbirdio/kubernetes-operator/internal/util"
)

// Annotations on an HTTPRoute that tune the NetBird reverse-proxy service the
// operator creates for it. They map onto fields of api.ServiceRequest that the
// reconciler would otherwise leave unset -- and therefore reset to their zero
// value on every reconcile, clobbering anything configured in the dashboard.
const (
	// servicePrivateAnnotation marks the service NetBird-only (mode=http).
	// Inbound peers authenticate via their tunnel identity; an ACL policy is
	// auto-generated from the access groups. Boolean.
	servicePrivateAnnotation = "netbird.io/private"
	// serviceAccessGroupsAnnotation is the comma-separated list of NetBird
	// group IDs whose peers may reach a private service. Required when
	// private=true, ignored otherwise.
	serviceAccessGroupsAnnotation = "netbird.io/access-groups"
	// serviceCrowdsecModeAnnotation sets CrowdSec IP-reputation handling:
	// off | observe | enforce. Only effective when the proxy cluster supports
	// CrowdSec.
	serviceCrowdsecModeAnnotation = "netbird.io/crowdsec-mode"
	// serviceAllowedCidrsAnnotation / serviceBlockedCidrsAnnotation are
	// comma-separated CIDR allow/block lists (allow evaluated first).
	serviceAllowedCidrsAnnotation = "netbird.io/allowed-cidrs"
	serviceBlockedCidrsAnnotation = "netbird.io/blocked-cidrs"
	// serviceAllowedCountriesAnnotation / serviceBlockedCountriesAnnotation are
	// comma-separated ISO 3166-1 alpha-2 country-code allow/block lists.
	serviceAllowedCountriesAnnotation = "netbird.io/allowed-countries"
	serviceBlockedCountriesAnnotation = "netbird.io/blocked-countries"
	// servicePassHostHeaderAnnotation / serviceRewriteRedirectsAnnotation
	// override the proxy header behaviour (both default to false). Boolean.
	servicePassHostHeaderAnnotation   = "netbird.io/pass-host-header"
	serviceRewriteRedirectsAnnotation = "netbird.io/rewrite-redirects"
)

// applyServiceAnnotations overlays the optional configuration carried on an
// HTTPRoute's annotations onto a freshly built api.ServiceRequest. Absent
// annotations leave the corresponding field untouched, preserving the
// reconciler's defaults. An invalid value is returned as an error so the
// reconcile surfaces it instead of silently dropping the setting.
func applyServiceAnnotations(hr *gwv1.HTTPRoute, req *api.ServiceRequest) error {
	a := hr.GetAnnotations()
	if a == nil {
		return nil
	}

	for ann, target := range map[string]**bool{
		servicePrivateAnnotation:          &req.Private,
		servicePassHostHeaderAnnotation:   &req.PassHostHeader,
		serviceRewriteRedirectsAnnotation: &req.RewriteRedirects,
	} {
		v, ok := a[ann]
		if !ok {
			continue
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("annotation %s: %w", ann, err)
		}
		*target = new(b)
	}

	if v, ok := a[serviceAccessGroupsAnnotation]; ok {
		groups := util.SplitTrim(v, ",")
		req.AccessGroups = &groups
	}

	ar, err := buildAccessRestrictions(a)
	if err != nil {
		return err
	}
	if ar != nil {
		req.AccessRestrictions = ar
	}

	return nil
}

// buildAccessRestrictions assembles an api.AccessRestrictions from the CrowdSec,
// CIDR and country annotations, or returns nil when none of them are present.
func buildAccessRestrictions(a map[string]string) (*api.AccessRestrictions, error) {
	var (
		ar  api.AccessRestrictions
		set bool
	)

	if v, ok := a[serviceCrowdsecModeAnnotation]; ok {
		mode := api.AccessRestrictionsCrowdsecMode(v)
		if !mode.Valid() {
			return nil, fmt.Errorf("annotation %s: invalid crowdsec mode %q (want off|observe|enforce)", serviceCrowdsecModeAnnotation, v)
		}
		ar.CrowdsecMode = new(mode)
		set = true
	}

	for ann, target := range map[string]**[]string{
		serviceAllowedCidrsAnnotation:     &ar.AllowedCidrs,
		serviceBlockedCidrsAnnotation:     &ar.BlockedCidrs,
		serviceAllowedCountriesAnnotation: &ar.AllowedCountries,
		serviceBlockedCountriesAnnotation: &ar.BlockedCountries,
	} {
		if v, ok := a[ann]; ok {
			list := util.SplitTrim(v, ",")
			*target = &list
			set = true
		}
	}

	if !set {
		return nil, nil
	}
	return &ar, nil
}
