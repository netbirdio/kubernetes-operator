// SPDX-License-Identifier: BSD-3-Clause

package netbirdutil

import (
	"context"
	"fmt"
	"slices"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func GetDNSZoneByName(ctx context.Context, nbClient *netbird.Client, name string) (api.Zone, error) {
	resp, err := nbClient.DNSZones.ListZones(ctx)
	if err != nil {
		return api.Zone{}, err
	}
	zoneIdx := slices.IndexFunc(resp, func(zone api.Zone) bool {
		return zone.Name == name
	})
	if zoneIdx == -1 {
		return api.Zone{}, fmt.Errorf("zone with name %s cannot be found", name)
	}
	return resp[zoneIdx], nil
}
