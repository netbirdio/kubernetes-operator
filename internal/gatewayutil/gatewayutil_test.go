// SPDX-License-Identifier: BSD-3-Clause

package gatewayutil

import (
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestReferencesGateway(t *testing.T) {
	t.Parallel()

	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "public", Namespace: "netbird"}}
	for _, tc := range []struct {
		name           string
		parent         gwv1.ParentReference
		routeNamespace string
		want           bool
	}{
		{
			name:           "same namespace by name",
			parent:         gwv1.ParentReference{Name: "public"},
			routeNamespace: "netbird",
			want:           true,
		},
		{
			name:           "other namespace by explicit namespace",
			parent:         gwv1.ParentReference{Name: "public", Namespace: new(gwv1.Namespace("netbird"))},
			routeNamespace: "default",
			want:           true,
		},
		{
			name:           "same name in the route's own namespace",
			parent:         gwv1.ParentReference{Name: "public"},
			routeNamespace: "default",
			want:           false,
		},
		{
			name:           "other gateway",
			parent:         gwv1.ParentReference{Name: "private"},
			routeNamespace: "netbird",
			want:           false,
		},
		{
			name: "defaulted group and kind",
			parent: gwv1.ParentReference{
				Group: new(gwv1.Group(gwv1.GroupName)),
				Kind:  new(gwv1.Kind("Gateway")),
				Name:  "public",
			},
			routeNamespace: "netbird",
			want:           true,
		},
		{
			name:           "parent of another kind",
			parent:         gwv1.ParentReference{Kind: new(gwv1.Kind("Service")), Name: "public"},
			routeNamespace: "netbird",
			want:           false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ReferencesGateway([]gwv1.ParentReference{tc.parent}, tc.routeNamespace, gw)
			assert.EqualT(t, tc.want, got, "parent %+v of a route in %s", tc.parent, tc.routeNamespace)
		})
	}
}
