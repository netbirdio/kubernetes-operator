package v1

import (
	"testing"

	"github.com/netbirdio/kubernetes-operator/internal/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConditionKeyEquivalence(t *testing.T) {
	c1 := NBCondition{
		Type:    NBSetupKeyReady,
		Status:  corev1.ConditionTrue,
		Reason:  "OK",
		Message: "all good",
	}
	c1WithTime := NBCondition{
		Type:               NBSetupKeyReady,
		Status:             corev1.ConditionTrue,
		Reason:             "OK",
		Message:            "all good",
		LastProbeTime:      metav1.Now(),
		LastTransitionTime: metav1.Now(),
	}
	c2 := NBCondition{
		Type:    NBSetupKeyReady,
		Status:  corev1.ConditionFalse,
		Reason:  "Failed",
		Message: "something broke",
	}

	tests := []struct {
		name string
		a    []NBCondition
		b    []NBCondition
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []NBCondition{}, []NBCondition{}, true},
		{"different lengths", []NBCondition{c1}, []NBCondition{}, false},
		{"same conditions", []NBCondition{c1}, []NBCondition{c1}, true},
		{"same semantic different timestamps", []NBCondition{c1}, []NBCondition{c1WithTime}, true},
		{"different conditions", []NBCondition{c1}, []NBCondition{c2}, false},
		{"same conditions different order", []NBCondition{c1, c2}, []NBCondition{c2, c1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := util.EquivalentBy(tt.a, tt.b, conditionKey); got != tt.want {
				t.Errorf("EquivalentBy(conditionKey) = %v, want %v", got, tt.want)
			}
		})
	}
}
