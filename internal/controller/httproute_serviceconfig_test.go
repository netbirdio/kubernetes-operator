// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"testing"

	"github.com/go-openapi/testify/v2/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func routeWith(annotations map[string]string) *gwv1.HTTPRoute {
	return &gwv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}}
}

func TestApplyServiceAnnotations(t *testing.T) {
	t.Parallel()

	t.Run("no annotations leaves request untouched", func(t *testing.T) {
		t.Parallel()
		req := api.ServiceRequest{Domain: "x", PassHostHeader: new(false)}
		require.NoError(t, applyServiceAnnotations(routeWith(nil), &req))
		require.Nil(t, req.Private)
		require.Nil(t, req.AccessGroups)
		require.Nil(t, req.AccessRestrictions)
		require.Equal(t, false, *req.PassHostHeader)
	})

	t.Run("private service with access groups", func(t *testing.T) {
		t.Parallel()
		req := api.ServiceRequest{}
		err := applyServiceAnnotations(routeWith(map[string]string{
			servicePrivateAnnotation:      "true",
			serviceAccessGroupsAnnotation: "grp-a, grp-b ,grp-c",
		}), &req)
		require.NoError(t, err)
		require.NotNil(t, req.Private)
		require.True(t, *req.Private)
		require.NotNil(t, req.AccessGroups)
		require.Equal(t, []string{"grp-a", "grp-b", "grp-c"}, *req.AccessGroups)
	})

	t.Run("crowdsec and geo restrictions", func(t *testing.T) {
		t.Parallel()
		req := api.ServiceRequest{}
		err := applyServiceAnnotations(routeWith(map[string]string{
			serviceCrowdsecModeAnnotation:     "enforce",
			serviceBlockedCountriesAnnotation: "RU,KP",
			serviceAllowedCidrsAnnotation:     "10.0.0.0/8",
		}), &req)
		require.NoError(t, err)
		require.NotNil(t, req.AccessRestrictions)
		require.NotNil(t, req.AccessRestrictions.CrowdsecMode)
		require.Equal(t, api.AccessRestrictionsCrowdsecModeEnforce, *req.AccessRestrictions.CrowdsecMode)
		require.Equal(t, []string{"RU", "KP"}, *req.AccessRestrictions.BlockedCountries)
		require.Equal(t, []string{"10.0.0.0/8"}, *req.AccessRestrictions.AllowedCidrs)
		require.Nil(t, req.AccessRestrictions.AllowedCountries)
	})

	t.Run("invalid crowdsec mode errors", func(t *testing.T) {
		t.Parallel()
		req := api.ServiceRequest{}
		err := applyServiceAnnotations(routeWith(map[string]string{
			serviceCrowdsecModeAnnotation: "panic",
		}), &req)
		require.Error(t, err)
	})

	t.Run("invalid bool errors", func(t *testing.T) {
		t.Parallel()
		req := api.ServiceRequest{}
		err := applyServiceAnnotations(routeWith(map[string]string{
			servicePrivateAnnotation: "yesplease",
		}), &req)
		require.Error(t, err)
	})
}
