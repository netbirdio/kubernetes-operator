// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
)

func TestNetbirdClientImage(t *testing.T) {
	t.Parallel()

	b, err := os.ReadFile("../../go.mod")
	require.NoError(t, err)
	f, err := modfile.Parse("go.mod", b, nil)
	require.NoError(t, err)
	idx := slices.IndexFunc(f.Require, func(r *modfile.Require) bool {
		return r.Mod.Path == "github.com/netbirdio/netbird"
	})
	require.GreaterT(t, idx, -1)
	modVersion := strings.TrimPrefix(f.Require[idx].Mod.Version, "v")

	start := strings.Index(NetbirdClientImage, ":") + 1
	end := strings.Index(NetbirdClientImage, "@")
	imgVersion := NetbirdClientImage[start:end]

	require.EqualT(t, modVersion, imgVersion)
}

func TestBuildVersionPrefersTheLinkedVersion(t *testing.T) {
	// Not parallel: it sets the package-level version.
	old := version
	t.Cleanup(func() { version = old })

	version = "v1.2.3"
	require.EqualT(t, "v1.2.3", BuildVersion())
}

func TestBuildInfoVersion(t *testing.T) {
	t.Parallel()

	clean := []debug.BuildSetting{{Key: "vcs.modified", Value: "false"}}
	for _, tc := range []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{name: "no build info", ok: false, want: "unknown"},
		{name: "clean tagged build", ok: true, want: "v0.8.0",
			bi: &debug.BuildInfo{Main: debug.Module{Version: "v0.8.0"}, Settings: clean}},
		{name: "modified tree", ok: true, want: "devel",
			bi: &debug.BuildInfo{Main: debug.Module{Version: "v0.8.0"}, Settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}}},
		{name: "no VCS details, as when building a file", ok: true, want: "devel",
			bi: &debug.BuildInfo{Main: debug.Module{Version: "v0.8.0"}}},
		{name: "no module version", ok: true, want: "devel",
			bi: &debug.BuildInfo{Settings: clean}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.EqualT(t, tc.want, buildInfoVersion(tc.bi, tc.ok), "version for %s", tc.name)
		})
	}
}

// TestMakefileSetsVersion builds a program with the -X flag the Makefile passes
// to the operator build. The linker ignores -X for a variable that does not
// exist, so only running the result shows the flag reaches BuildVersion.
func TestMakefileSetsVersion(t *testing.T) {
	t.Parallel()

	makefile, err := os.ReadFile("../../Makefile")
	require.NoError(t, err)
	m := regexp.MustCompile(`-X (\S+)=\$\(VERSION\)`).FindSubmatch(makefile)
	require.NotNil(t, m, "the Makefile passes no -X ...=$(VERSION) to the operator build")

	bin := filepath.Join(t.TempDir(), "printversion")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "-ldflags", "-X "+string(m[1])+"=v9.9.9-test", "./testdata/printversion")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build: %s", out)

	out, err = exec.Command(bin).Output()
	require.NoError(t, err)
	assert.EqualT(t, "v9.9.9-test", string(out), "the version the Makefile's -X flag sets")
}
