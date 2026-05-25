// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

func ClientImage() string {
	return "ghcr.io/netbirdio/netbird:0.71.4@sha256:c4195811bf9999544db5176950a0d6513c880d0195450b59eb156c254e0dd3b5"
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
