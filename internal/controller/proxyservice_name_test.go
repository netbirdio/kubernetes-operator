// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestProxyServiceName(t *testing.T) {
	uid := uuid.New().String()

	if got, want := proxyServiceName("test.example.com", uid), "test.example.com:"+proxyServiceOwner+":"+uid; got != want {
		t.Errorf("proxyServiceName() = %q, want %q", got, want)
	}

	// The hostname is shortened (the owner marker and full UID are kept)
	// when the name would exceed the 255 character limit.
	long := strings.Repeat("a", 300)
	marker := ":" + proxyServiceOwner + ":" + uid
	want := long[:255-len(marker)] + marker
	if got := proxyServiceName(long, uid); got != want {
		t.Errorf("proxyServiceName() for long hostname = %q, want %q", got, want)
	}
	if len(want) > 255 {
		t.Errorf("proxyServiceName() for long hostname = %d chars, want <= 255", len(want))
	}
}
