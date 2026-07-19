// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

const (
	NetbirdClientImage       = "ghcr.io/netbirdio/netbird:0.74.7@sha256:b63f4c1584118aeebacfdfd841f0351122a53fccac182b4c43be428c2c9a6b73"
	KubeApiProxyImage        = "ghcr.io/netbirdio/netbird-kubeapi-proxy:v0.0.4@sha256:bffa4f093abc19b4934ae37657bac76fa3b390cbd39aadac987634215eb750f5"
	KubeEgressForwarderImage = "ghcr.io/netbirdio/kube-egress-forwarder:v0.0.2@sha256:f3b4637122cbda3c1915d49e6f96edff7e3a3accfceb87b821c829056abe8a6f"
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
