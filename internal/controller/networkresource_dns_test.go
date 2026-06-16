// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"testing"

	"github.com/go-openapi/testify/v2/require"
)

func TestRecordMatchKey(t *testing.T) {
	t.Parallel()

	// The same IPv6 address in different textual forms must key identically,
	// so an AAAA record is adopted rather than deleted + recreated.
	require.Equal(t,
		recordMatchKey("AAAA", "2001:db8::1"),
		recordMatchKey("AAAA", "2001:0db8:0000:0000:0000:0000:0000:0001"),
	)

	// Type is part of the key.
	require.NotEqual(t,
		recordMatchKey("A", "2001:db8::1"),
		recordMatchKey("AAAA", "2001:db8::1"),
	)

	// IPv4 keys match themselves.
	require.Equal(t, recordMatchKey("A", "10.0.0.1"), recordMatchKey("A", "10.0.0.1"))

	// Non-IP content falls back to the raw string.
	require.Equal(t, "CNAME|example.com", recordMatchKey("CNAME", "example.com"))
}
