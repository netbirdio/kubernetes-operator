// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

const (
	NetbirdClientImage       = "ghcr.io/netbirdio/netbird:0.82.0@sha256:eca5b274c635bfbb04ec6724a0712d1146190dd450eea199eeb83916fdd94965"
	KubeApiProxyImage        = "ghcr.io/netbirdio/netbird-kubeapi-proxy:v0.0.6@sha256:d346f9bebda435d6eeb69dd9ab8e6074eda6aaa36eca73e9bb91ef7d562ab045"
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
