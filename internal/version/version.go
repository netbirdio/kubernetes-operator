// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"runtime/debug"
)

func ClientImage() string {
	return "ghcr.io/netbirdio/netbird:0.71.2@sha256:a2cc19dd02fdc3bfe54bab10cde5715265fc82f6e9d034edc1183ad57d07c22e"
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
