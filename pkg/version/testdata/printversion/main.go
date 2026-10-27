// SPDX-License-Identifier: BSD-3-Clause

// Command printversion prints version.BuildVersion, so a test can build it with
// the Makefile's linker flags and see the version they set.
package main

import (
	"fmt"

	"github.com/netbirdio/kubernetes-operator/pkg/version"
)

func main() {
	fmt.Print(version.BuildVersion())
}
