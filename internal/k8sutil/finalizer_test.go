// SPDX-License-Identifier: BSD-3-Clause

package k8sutil

import (
	"testing"

	"github.com/go-openapi/testify/v2/require"
)

func TestFinalizer(t *testing.T) {
	t.Parallel()

	res := Finalizer("foo")
	require.Equal(t, "finalizers.netbird.io/foo", res)
}
