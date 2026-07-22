// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

const (
	NetbirdClientImage       = "ghcr.io/netbirdio/netbird:0.74.7@sha256:b63f4c1584118aeebacfdfd841f0351122a53fccac182b4c43be428c2c9a6b73"
	KubeApiProxyImage        = "ghcr.io/netbirdio/netbird-kubeapi-proxy:v0.0.4@sha256:bffa4f093abc19b4934ae37657bac76fa3b390cbd39aadac987634215eb750f5"
	KubeEgressForwarderImage = "ghcr.io/netbirdio/kube-egress-forwarder:v0.0.3@sha256:8095e8fe03f28c91b9b7bd55617c582143d66fcc5d9bd8264302c97d03c01360"
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
