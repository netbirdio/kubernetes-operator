// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestSelectRouter(t *testing.T) {
	t.Parallel()

	recorded := "r2"
	missing := "gone"
	orders := [][]api.NetworkRouter{
		{{Id: "r1"}, {Id: "r2"}, {Id: "r3"}},
		{{Id: "r3"}, {Id: "r1"}, {Id: "r2"}},
		{{Id: "r2"}, {Id: "r3"}, {Id: "r1"}},
	}

	for _, routers := range orders {
		router := selectRouter(routers, &recorded)
		require.NotNil(t, router)
		assert.EqualT(t, "r2", router.Id, "recorded router should be selected regardless of list order")

		router = selectRouter(routers, nil)
		require.NotNil(t, router)
		assert.EqualT(t, "r1", router.Id, "lowest ID should be selected when none is recorded")

		router = selectRouter(routers, &missing)
		require.NotNil(t, router)
		assert.EqualT(t, "r1", router.Id, "lowest ID should be selected when the recorded router is gone")
	}

	assert.Nil(t, selectRouter(nil, &recorded), "no router should be selected from an empty list")
}

func TestRouterUpToDate(t *testing.T) {
	t.Parallel()

	router := &api.NetworkRouter{Enabled: true, Masquerade: true, Metric: 9999, PeerGroups: &[]string{"g1"}}
	assert.True(t, routerUpToDate(router, "g1"), "router with operator settings should be up to date")
	assert.False(t, routerUpToDate(router, "g2"), "router with a different peer group should not be up to date")
	assert.False(t, routerUpToDate(&api.NetworkRouter{Enabled: true, Masquerade: true, Metric: 9999}, "g1"), "router without peer groups should not be up to date")
}

func TestFindGroupByName(t *testing.T) {
	t.Parallel()

	recorded := "g3"
	orders := [][]api.Group{
		{{Id: "g2", Name: "dup"}, {Id: "g3", Name: "dup"}, {Id: "g1", Name: "other"}},
		{{Id: "g3", Name: "dup"}, {Id: "g1", Name: "other"}, {Id: "g2", Name: "dup"}},
	}

	for _, groups := range orders {
		group := findGroupByName(groups, "dup", &recorded)
		require.NotNil(t, group)
		assert.EqualT(t, "g3", group.Id, "recorded group should win among duplicate names")

		group = findGroupByName(groups, "dup", nil)
		require.NotNil(t, group)
		assert.EqualT(t, "g2", group.Id, "lowest ID should win among duplicate names when none is recorded")
	}

	assert.Nil(t, findGroupByName([]api.Group{{Id: "g1", Name: "other"}}, "dup", nil), "missing name should return nil")
}
