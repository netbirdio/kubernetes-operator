// SPDX-License-Identifier: BSD-3-Clause

package v1

import (
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNBPolicyStatusEqualComparesPointersByValue(t *testing.T) {
	t.Parallel()

	tcp := "tcp-policy"
	udp := "udp-policy"
	status := NBPolicyStatus{
		TCPPolicyID:        &tcp,
		UDPPolicyID:        &udp,
		LastUpdatedAt:      &metav1.Time{Time: time.Unix(1000, 0)},
		ManagedServiceList: []string{"default/a", "default/b"},
		Conditions:         NBConditionTrue(),
	}

	// The reconciler compares a deep copy with the status it rebuilt, so equal values
	// behind different pointers must match.
	require.True(t, status.Equal(*status.DeepCopy()), "status with equal values should be equal")
	require.True(t, NBPolicyStatus{}.Equal(NBPolicyStatus{}), "status without pointers set should be equal")

	changed := *status.DeepCopy()
	other := "other-policy"
	changed.TCPPolicyID = &other
	require.False(t, status.Equal(changed), "different TCP policy ID should not be equal")

	changed = *status.DeepCopy()
	changed.UDPPolicyID = nil
	require.False(t, status.Equal(changed), "missing UDP policy ID should not be equal")

	changed = *status.DeepCopy()
	changed.LastUpdatedAt = &metav1.Time{Time: time.Unix(2000, 0)}
	require.False(t, status.Equal(changed), "different LastUpdatedAt should not be equal")

	changed = *status.DeepCopy()
	changed.LastUpdatedAt = nil
	require.False(t, status.Equal(changed), "missing LastUpdatedAt should not be equal")
}

func TestNBPolicyStatusEqualIgnoresConditionTimes(t *testing.T) {
	t.Parallel()

	// No pointers are set, so only the conditions can tell the statuses apart.
	status := NBPolicyStatus{
		ManagedServiceList: []string{"default/a"},
		Conditions:         NBConditionTrue(),
	}

	// The reconciler stamps fresh condition times on every pass.
	restamped := *status.DeepCopy()
	restamped.Conditions[0].LastProbeTime = metav1.NewTime(time.Now().Add(time.Hour))
	restamped.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(time.Hour))
	require.True(t, status.Equal(restamped), "status differing only in condition times should be equal")

	changed := *status.DeepCopy()
	changed.Conditions = NBConditionFalse("APIError", "boom")
	require.False(t, status.Equal(changed), "different condition status should not be equal")
}
