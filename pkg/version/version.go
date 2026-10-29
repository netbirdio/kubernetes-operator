// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

const (
	NetbirdClientImage       = "ghcr.io/netbirdio/netbird:0.81.4@sha256:0911a96049d95a37ee1653663a0d9005f77a0096a1dc0cac45d9c3a022256e85"
	KubeApiProxyImage        = "ghcr.io/netbirdio/netbird-kubeapi-proxy:v0.0.5@sha256:af3c0b747d1ef307556ade3d1b59cf79cea6deac01f5c9d4ddd48f4e1154599a"
	KubeEgressForwarderImage = "ghcr.io/netbirdio/kube-egress-forwarder:v0.0.3@sha256:8095e8fe03f28c91b9b7bd55617c582143d66fcc5d9bd8264302c97d03c01360"
)

// version is the operator version the build sets with
// -ldflags "-X github.com/netbirdio/kubernetes-operator/pkg/version.version=...".
// The Makefile builds cmd/main.go as a file, which leaves the module version
// and VCS details out of the build info, so this is the only version a release
// binary carries.
var version string

// BuildVersion returns the operator version: the one set at build time, or else
// the module version from the build info, or "devel" for a build of a modified
// or unversioned tree.
func BuildVersion() string {
	if version != "" {
		return version
	}
	bi, ok := debug.ReadBuildInfo()
	return buildInfoVersion(bi, ok)
}

func buildInfoVersion(bi *debug.BuildInfo, ok bool) string {
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
