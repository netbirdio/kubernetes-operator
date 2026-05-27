// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

const (
	NetbirdClientImage = "ghcr.io/netbirdio/netbird:0.71.4@sha256:c4195811bf9999544db5176950a0d6513c880d0195450b59eb156c254e0dd3b5"
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
