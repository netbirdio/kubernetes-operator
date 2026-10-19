// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// TestValidation feeds the API server what the CRDs' validation rules must
// refuse. A rule that never fires in a test is a rejection nobody has confirmed
// happens. Every case runs as a dry run, and each kind is first shown to accept
// a valid object, so a rejection cannot come from something else being wrong.
func TestValidation(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	ns := e.createNamespace(t, "validation")

	t.Run("create", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			manifest string
			// wantErr is a substring of the rejection, or empty for an object that
			// must be accepted.
			wantErr string
		}{
			{
				name:     "valid group",
				manifest: `{kind: Group, spec: {name: e2e-valid}}`,
			},
			{
				name:     "group without a name",
				manifest: `{kind: Group, spec: {name: ""}}`,
				wantErr:  "spec.name",
			},
			{
				name:     "valid setup key",
				manifest: `{kind: SetupKey, spec: {name: e2e-valid, ephemeral: true, duration: 24h, autoGroups: [{name: All}]}}`,
			},
			{
				name:     "setup key duration in days",
				manifest: `{kind: SetupKey, spec: {name: e2e-days, ephemeral: true, duration: 1d}}`,
				wantErr:  "spec.duration",
			},
			{
				name:     "group reference by name and id at once",
				manifest: `{kind: SetupKey, spec: {name: e2e-ref, ephemeral: true, autoGroups: [{name: All, id: abc}]}}`,
				wantErr:  "Exactly one of id, name, or localRef",
			},
			{
				name:     "valid network router",
				manifest: `{kind: NetworkRouter, spec: {dnsZoneRef: {name: example.com}, workloadOverride: {replicas: 1}}}`,
			},
			{
				name:     "network router without replicas",
				manifest: `{kind: NetworkRouter, spec: {dnsZoneRef: {name: example.com}, workloadOverride: {replicas: 0}}}`,
				wantErr:  "spec.workloadOverride.replicas",
			},
			{
				name:     "valid network egress",
				manifest: `{kind: NetworkEgress, spec: {networkRouterRef: {name: router, namespace: router-ns}, target: {ip: {address: 10.0.0.1}}, ports: [{name: http, port: 80}]}}`,
			},
			{
				name:     "egress to something that is not an IP",
				manifest: `{kind: NetworkEgress, spec: {networkRouterRef: {name: router, namespace: router-ns}, target: {ip: {address: 10.0.0.0/24}}, ports: [{name: http, port: 80}]}}`,
				wantErr:  "address must be a valid IPv4 or IPv6 address",
			},
			{
				name:     "egress to an IP and an FQDN at once",
				manifest: `{kind: NetworkEgress, spec: {networkRouterRef: {name: router, namespace: router-ns}, target: {ip: {address: 10.0.0.1}, fqdn: {hostname: example.com}}, ports: [{name: http, port: 80}]}}`,
				wantErr:  "exactly one of ip or fqdn must be set",
			},
			{
				name:     "egress to a wildcard",
				manifest: `{kind: NetworkEgress, spec: {networkRouterRef: {name: router, namespace: router-ns}, target: {fqdn: {hostname: "*.example.com"}}, ports: [{name: http, port: 80}]}}`,
				wantErr:  "spec.target.fqdn.hostname",
			},
			{
				name:     "egress without ports",
				manifest: `{kind: NetworkEgress, spec: {networkRouterRef: {name: router, namespace: router-ns}, target: {ip: {address: 10.0.0.1}}, ports: []}}`,
				wantErr:  "spec.ports",
			},
			{
				name:     "egress port out of range",
				manifest: `{kind: NetworkEgress, spec: {networkRouterRef: {name: router, namespace: router-ns}, target: {ip: {address: 10.0.0.1}}, ports: [{name: http, port: 65536}]}}`,
				wantErr:  "spec.ports[0].port",
			},
			{
				name:     "egress port name with capitals",
				manifest: `{kind: NetworkEgress, spec: {networkRouterRef: {name: router, namespace: router-ns}, target: {ip: {address: 10.0.0.1}}, ports: [{name: HTTP, port: 80}]}}`,
				wantErr:  "spec.ports[0].name",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				obj := manifest(t, ns, "valid", tc.manifest)
				err := e.k8s.Create(t.Context(), obj, client.DryRunAll)
				if tc.wantErr == "" {
					require.NoError(t, err)
					return
				}
				require.Error(t, err, "the API server accepted %s", tc.manifest)
				assert.Contains(t, err.Error(), tc.wantErr, "rejected for another reason")
			})
		}
	})

	t.Run("update", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			manifest string
			// field is the path to change and value what to change it to.
			field   []string
			value   any
			wantErr string
		}{
			{
				name:     "setup key ephemeral",
				manifest: `{kind: SetupKey, spec: {name: e2e-immutable-ephemeral, ephemeral: true}}`,
				field:    []string{"spec", "ephemeral"},
				value:    false,
				wantErr:  "ephemeral is immutable",
			},
			{
				name:     "setup key extra DNS labels",
				manifest: `{kind: SetupKey, spec: {name: e2e-immutable-labels, ephemeral: true, allowExtraDnsLabels: false}}`,
				field:    []string{"spec", "allowExtraDnsLabels"},
				value:    true,
				wantErr:  "allowExtraDnsLabels is immutable",
			},
			{
				name:     "setup key duration",
				manifest: `{kind: SetupKey, spec: {name: e2e-immutable-duration, ephemeral: true, duration: 24h}}`,
				field:    []string{"spec", "duration"},
				value:    "48h",
				wantErr:  "duration is immutable",
			},
			{
				name:     "network resource router",
				manifest: `{kind: NetworkResource, spec: {networkRouterRef: {name: router, namespace: router-ns}, serviceRef: {name: s}}}`,
				field:    []string{"spec", "networkRouterRef", "name"},
				value:    "other",
				wantErr:  "Value is immutable",
			},
			{
				name:     "network egress router",
				manifest: `{kind: NetworkEgress, spec: {networkRouterRef: {name: router, namespace: router-ns}, target: {ip: {address: 10.0.0.1}}, ports: [{name: http, port: 80}]}}`,
				field:    []string{"spec", "networkRouterRef", "namespace"},
				value:    "other",
				wantErr:  "Value is immutable",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				obj := manifest(t, ns, sanitizeName(tc.name), tc.manifest)
				require.NoError(t, e.k8s.Create(t.Context(), obj))
				t.Cleanup(func() {
					_ = e.k8s.Delete(context.Background(), obj)
				})
				// A merge patch rather than an update: the operator writes finalizers
				// and status meanwhile, and an update would fail on the stale
				// resourceVersion before validation ever ran.
				change := map[string]any{}
				require.NoError(t, unstructured.SetNestedField(change, tc.value, tc.field...))
				body, err := json.Marshal(change)
				require.NoError(t, err)
				err = e.k8s.Patch(t.Context(), obj, client.RawPatch(types.MergePatchType, body), client.DryRunAll)
				require.Error(t, err, "the API server accepted a change to %v", tc.field)
				assert.Contains(t, err.Error(), tc.wantErr, "rejected for another reason")
			})
		}
	})
}

// manifest builds an operator object from a compact YAML document holding its
// kind and spec. The documents are read as YAML 1.1, where a bare y or n is a
// boolean, so short placeholder names are spelled out.
func manifest(t *testing.T, namespace, name, doc string) *unstructured.Unstructured {
	t.Helper()
	obj := &unstructured.Unstructured{}
	require.NoError(t, yaml.Unmarshal([]byte(doc), &obj.Object))
	obj.SetAPIVersion("netbird.io/v1alpha1")
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}

// sanitizeName turns a test case name into an object name.
func sanitizeName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}
