package version

import (
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"

	"github.com/go-openapi/testify/v2/require"
)

func TestClientImage(t *testing.T) {
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

	clientImg := ClientImage()
	start := strings.Index(clientImg, ":") + 1
	end := strings.Index(clientImg, "@")
	imgVersion := clientImg[start:end]

	require.EqualT(t, modVersion, imgVersion)
}
