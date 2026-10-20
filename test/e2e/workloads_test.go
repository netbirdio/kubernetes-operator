// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

const (
	// agnhost netexec answers /hostname with its pod's name, so a response says
	// which workload a request reached.
	agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"
	backendPort  = 8080

	readyTimeout = 5 * time.Minute
)

// conditionedObject is a CRD the operator reports a Ready condition on.
type conditionedObject interface {
	client.Object
	GetConditions() []metav1.Condition
}

// waitReady waits until the operator reports the object Ready for its current
// generation, and returns with obj holding that state.
func (e *environment) waitReady(t *testing.T, obj conditionedObject) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		cond := meta.FindStatusCondition(obj.GetConditions(), nbv1alpha1.ReadyCondition)
		if cond == nil {
			return fmt.Errorf("%s has no Ready condition yet", obj.GetName())
		}
		if cond.ObservedGeneration != obj.GetGeneration() || cond.Status != metav1.ConditionTrue {
			return fmt.Errorf("%s is not ready for generation %d: %s %s: %s",
				obj.GetName(), obj.GetGeneration(), cond.Status, cond.Reason, cond.Message)
		}
		return nil
	}, readyTimeout, 2*time.Second)
}

// waitGone waits until a deleted object, finalizers and all, is gone.
func (e *environment) waitGone(t *testing.T, obj client.Object) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		err := e.k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj)
		if err == nil {
			return fmt.Errorf("%s still exists, finalizers %v", obj.GetName(), obj.GetFinalizers())
		}
		return client.IgnoreNotFound(err)
	}, readyTimeout, 2*time.Second)
}

// createRouter creates a NetworkRouter in the fixture DNS zone and waits until
// its routing peers are up.
func (e *environment) createRouter(t *testing.T, namespace, name string, replicas int32) *nbv1alpha1.NetworkRouter {
	t.Helper()
	router := &nbv1alpha1.NetworkRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: nbv1alpha1.NetworkRouterSpec{
			DNSZoneRef: nbv1alpha1.DNSZoneReference{Name: dnsZone},
			WorkloadOverride: &nbv1alpha1.WorkloadOverride{
				Replicas: &replicas,
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), router))
	e.waitReady(t, router)
	return router
}

// createBackend deploys an HTTP server behind a ClusterIP Service of the same
// name and waits until it serves.
func (e *environment) createBackend(t *testing.T, namespace, name string) *corev1.Service {
	t.Helper()
	labels := map[string]string{"app": name}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "http",
							Image: agnhostImage,
							Args:  []string{"netexec", fmt.Sprintf("--http-port=%d", backendPort)},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{Path: "/hostname", Port: intstr.FromInt32(backendPort)},
								},
							},
						},
					},
				},
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), dep))
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       backendPort,
					TargetPort: intstr.FromInt32(backendPort),
				},
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), svc))
	require.Eventually(t, func(ctx context.Context) error {
		return e.workloadCurrent(ctx, "Deployment", namespace, name)
	}, readyTimeout, 2*time.Second)
	return svc
}
