// SPDX-License-Identifier: BSD-3-Clause

package v1

import (
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// restamp mimics a reconcile that sets the same condition again a moment later.
func restamp(conditions []NBCondition) []NBCondition {
	out := make([]NBCondition, len(conditions))
	copy(out, conditions)
	for i := range out {
		out[i].LastProbeTime = metav1.NewTime(out[i].LastProbeTime.Add(time.Minute))
		out[i].LastTransitionTime = metav1.NewTime(out[i].LastTransitionTime.Add(time.Minute))
	}
	return out
}

func TestStatusEqualUnchanged(t *testing.T) {
	t.Parallel()

	id := "id"
	now := metav1.Now()

	policy := NBPolicyStatus{TCPPolicyID: &id, UDPPolicyID: &id, LastUpdatedAt: &now, ManagedServiceList: []string{"ns/a", "ns/b"}, Conditions: NBConditionTrue()}
	policyCopy := *policy.DeepCopy()
	policyCopy.Conditions = restamp(policyCopy.Conditions)
	policyCopy.ManagedServiceList = []string{"ns/b", "ns/a"}
	assert.True(t, policy.Equal(policyCopy), "NBPolicyStatus should equal its deep copy with re-stamped conditions")

	resource := NBResourceStatus{NetworkResourceID: &id, PolicyName: &id, Groups: []string{"g1", "g2"}, Conditions: NBConditionTrue()}
	resourceCopy := *resource.DeepCopy()
	resourceCopy.Conditions = restamp(resourceCopy.Conditions)
	assert.True(t, resource.Equal(resourceCopy), "NBResourceStatus should equal its deep copy with re-stamped conditions")

	routingPeer := NBRoutingPeerStatus{NetworkID: &id, SetupKeyID: &id, RouterID: &id, Conditions: NBConditionTrue()}
	routingPeerCopy := *routingPeer.DeepCopy()
	routingPeerCopy.Conditions = restamp(routingPeerCopy.Conditions)
	assert.True(t, routingPeer.Equal(routingPeerCopy), "NBRoutingPeerStatus should equal its deep copy with re-stamped conditions")

	group := NBGroupStatus{GroupID: &id, Conditions: NBConditionTrue()}
	groupCopy := *group.DeepCopy()
	groupCopy.Conditions = restamp(groupCopy.Conditions)
	assert.True(t, group.Equal(groupCopy), "NBGroupStatus should equal its deep copy with re-stamped conditions")
}

func TestStatusEqualChanged(t *testing.T) {
	t.Parallel()

	id, other := "id", "other"
	later := metav1.NewTime(time.Now().Add(time.Hour))
	now := metav1.Now()

	policy := NBPolicyStatus{TCPPolicyID: &id, LastUpdatedAt: &now, Conditions: NBConditionTrue()}
	assert.False(t, policy.Equal(NBPolicyStatus{TCPPolicyID: &other, LastUpdatedAt: &now, Conditions: policy.Conditions}), "different TCP policy ID should not be equal")
	assert.False(t, policy.Equal(NBPolicyStatus{TCPPolicyID: &id, LastUpdatedAt: &later, Conditions: policy.Conditions}), "different LastUpdatedAt should not be equal")
	assert.False(t, policy.Equal(NBPolicyStatus{TCPPolicyID: &id, LastUpdatedAt: &now, Conditions: NBConditionFalse("APIError", "boom")}), "condition status change should not be equal")

	resource := NBResourceStatus{NetworkResourceID: &id}
	assert.False(t, resource.Equal(NBResourceStatus{}), "nil and set resource ID should not be equal")

	routingPeer := NBRoutingPeerStatus{RouterID: &id}
	assert.False(t, routingPeer.Equal(NBRoutingPeerStatus{RouterID: &other}), "different router IDs should not be equal")

	group := NBGroupStatus{GroupID: &id, Conditions: NBConditionFalse("APIError", "a")}
	assert.False(t, group.Equal(NBGroupStatus{GroupID: &id, Conditions: NBConditionFalse("APIError", "b")}), "different condition message should not be equal")
}
