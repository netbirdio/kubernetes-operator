// SPDX-License-Identifier: BSD-3-Clause

package util

import (
	"testing"

	"github.com/go-openapi/testify/v2/assert"
)

func TestEquivalent(t *testing.T) {
	t.Parallel()

	assert.True(t, Equivalent([]string{"a", "b", "c"}, []string{"c", "a", "b"}), "order should not matter")
	assert.True(t, Equivalent[string](nil, []string{}), "nil and empty should be equivalent")
	assert.False(t, Equivalent([]string{"a", "a", "b"}, []string{"a", "b", "b"}), "duplicate counts should matter")
	assert.False(t, Equivalent([]string{"a"}, []string{"a", "a"}), "different lengths should not be equivalent")
	assert.False(t, Equivalent([]string{"a", "b"}, []string{"a", "c"}), "different elements should not be equivalent")
}

func TestPtrEqual(t *testing.T) {
	t.Parallel()

	a, b, c := "id", "id", "other"
	assert.True(t, PtrEqual[string](nil, nil), "two nil pointers should be equal")
	assert.True(t, PtrEqual(&a, &b), "distinct pointers to equal values should be equal")
	assert.False(t, PtrEqual(&a, &c), "pointers to different values should not be equal")
	assert.False(t, PtrEqual(&a, nil), "nil and non-nil should not be equal")
	assert.False(t, PtrEqual(nil, &a), "nil and non-nil should not be equal")
}
