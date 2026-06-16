// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"reflect"
	"sort"

	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// pathPrefixFor returns the URL path prefix a rule's targets should carry,
// taken from the rule's first PathPrefix/Exact match, or nil when the rule has
// no usable path match (a catch-all). RegularExpression matches are skipped —
// the NetBird target Path is a prefix, not a regex.
func pathPrefixFor(rule gwv1.HTTPRouteRule) *string {
	for _, m := range rule.Matches {
		if m.Path == nil || m.Path.Value == nil {
			continue
		}
		t := gwv1.PathMatchPathPrefix
		if m.Path.Type != nil {
			t = *m.Path.Type
		}
		if t == gwv1.PathMatchPathPrefix || t == gwv1.PathMatchExact {
			return m.Path.Value
		}
	}
	return nil
}

// sortTargets orders targets deterministically so the rendered ServiceRequest
// is stable across reconciles (otherwise map iteration order would make every
// reconcile look like a change).
func sortTargets(targets []api.ServiceTarget) {
	sort.Slice(targets, func(i, j int) bool {
		a, b := targets[i], targets[j]
		if a.TargetId != b.TargetId {
			return a.TargetId < b.TargetId
		}
		if derefStr(a.Path) != derefStr(b.Path) {
			return derefStr(a.Path) < derefStr(b.Path)
		}
		return a.Port < b.Port
	})
}

// proxyServiceUpToDate reports whether the live reverse-proxy service already
// matches the desired request for the fields the operator manages, so an
// unchanged reconcile can skip the PUT.
func proxyServiceUpToDate(existing api.Service, req api.ServiceRequest) bool {
	return reflect.DeepEqual(proxyStateFromService(existing), proxyStateFromRequest(req))
}

// proxyState is a normalized projection of the managed fields of a reverse-proxy
// service, with nil/empty collapsed so nil-vs-empty doesn't read as a change.
type proxyState struct {
	enabled          bool
	name             string
	mode             string
	passHostHeader   bool
	rewriteRedirects bool
	private          bool
	accessGroups     []string
	crowdsec         string
	allowedCidrs     []string
	blockedCidrs     []string
	allowedCountries []string
	blockedCountries []string
	targets          []targetState
}

type targetState struct {
	enabled    bool
	path       string
	port       int
	protocol   string
	targetType string
	targetID   string
}

func proxyStateFromRequest(req api.ServiceRequest) proxyState {
	s := proxyState{
		enabled:          req.Enabled,
		name:             req.Name,
		passHostHeader:   derefBool(req.PassHostHeader),
		rewriteRedirects: derefBool(req.RewriteRedirects),
		private:          derefBool(req.Private),
		accessGroups:     normSlice(derefSlice(req.AccessGroups)),
	}
	if req.Mode != nil {
		s.mode = string(*req.Mode)
	}
	s.crowdsec, s.allowedCidrs, s.blockedCidrs, s.allowedCountries, s.blockedCountries = restrictionState(req.AccessRestrictions)
	if req.Targets != nil {
		s.targets = targetStates(*req.Targets)
	}
	return s
}

func proxyStateFromService(svc api.Service) proxyState {
	s := proxyState{
		enabled:          svc.Enabled,
		name:             svc.Name,
		passHostHeader:   derefBool(svc.PassHostHeader),
		rewriteRedirects: derefBool(svc.RewriteRedirects),
		private:          derefBool(svc.Private),
		accessGroups:     normSlice(derefSlice(svc.AccessGroups)),
		targets:          targetStates(svc.Targets),
	}
	if svc.Mode != nil {
		s.mode = string(*svc.Mode)
	}
	s.crowdsec, s.allowedCidrs, s.blockedCidrs, s.allowedCountries, s.blockedCountries = restrictionState(svc.AccessRestrictions)
	return s
}

func restrictionState(ar *api.AccessRestrictions) (crowdsec string, allowedCidrs, blockedCidrs, allowedCountries, blockedCountries []string) {
	if ar == nil {
		return "", nil, nil, nil, nil
	}
	if ar.CrowdsecMode != nil {
		crowdsec = string(*ar.CrowdsecMode)
	}
	return crowdsec,
		normSlice(derefSlice(ar.AllowedCidrs)),
		normSlice(derefSlice(ar.BlockedCidrs)),
		normSlice(derefSlice(ar.AllowedCountries)),
		normSlice(derefSlice(ar.BlockedCountries))
}

func targetStates(targets []api.ServiceTarget) []targetState {
	if len(targets) == 0 {
		return nil
	}
	out := make([]targetState, 0, len(targets))
	for _, t := range targets {
		out = append(out, targetState{
			enabled:    t.Enabled,
			path:       derefStr(t.Path),
			port:       t.Port,
			protocol:   string(t.Protocol),
			targetType: string(t.TargetType),
			targetID:   t.TargetId,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].targetID != out[j].targetID {
			return out[i].targetID < out[j].targetID
		}
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		return out[i].port < out[j].port
	})
	return out
}

func derefBool(b *bool) bool {
	return b != nil && *b
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefSlice(s *[]string) []string {
	if s == nil {
		return nil
	}
	return *s
}

// normSlice collapses an empty slice to nil so it compares equal to an unset
// field.
func normSlice(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
