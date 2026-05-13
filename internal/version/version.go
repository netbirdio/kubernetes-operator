// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

func ClientImage() string {
	return "ghcr.io/netbirdio/netbird:0.70.4@sha256:3a28b9f7f32875c6a35f952ca7e9cb688b1e610365365ff55f6e790da3950f55"
}

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
