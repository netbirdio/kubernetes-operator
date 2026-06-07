// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

const (
	NetbirdClientImage = "ghcr.io/netbirdio/netbird:0.72.2@sha256:22038909f0dfb7fec7d6353ab42a949fd4af41627b6a8866be75078b396e00f5"
	KubeApiProxyImage  = "ghcr.io/netbirdio/netbird-kubeapi-proxy:v0.0.1@sha256:aa5bbdfc2eca51438f3d50ed4441d61388e9a8d2d5dc886cc4988dacd36ad648"
)

func BuildVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	modified := true
	for _, s := range bi.Settings {
		if s.Key == "vcs.modified" {
			if s.Value == "false" {
				modified = false
			}
			break
		}
	}

	develVersion := "devel"
	if modified {
		return develVersion
	}
	if bi.Main.Version == "" {
		return develVersion
	}
	return bi.Main.Version
}
