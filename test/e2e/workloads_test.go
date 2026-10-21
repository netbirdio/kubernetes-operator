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
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

const (
	// agnhost netexec answers /hostname with its pod's name, so a response says
	// which workload a request reached.
	agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"
	backendPort  = 8080
	// backendServicePort is the port a backend's Service exposes. It is the
	// default HTTP port so a request to a network resource needs no port of its
	// own; TestHTTPRouteBackendPort covers a Service on another one.
	backendServicePort = 80

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
	require.NoError(t, e.waitReadyCtx(t.Context(), obj))
}

// waitReadyWithin is waitReady with its own timeout, for a test that expects
// the operator to act faster than readyTimeout allows.
func (e *environment) waitReadyWithin(t *testing.T, obj conditionedObject, timeout time.Duration) {
	t.Helper()
	require.NoError(t, e.waitReadyFor(t.Context(), obj, timeout))
}

func (e *environment) waitReadyCtx(ctx context.Context, obj conditionedObject) error {
	return e.waitReadyFor(ctx, obj, readyTimeout)
}

func (e *environment) waitReadyFor(ctx context.Context, obj conditionedObject, timeout time.Duration) error {
	return eventually(ctx, timeout, func(ctx context.Context) error {
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
	})
}

// eventually polls fn until it succeeds and, when the timeout passes first,
// returns the last error fn gave, which is the one that says what was missing.
// An attempt the deadline cut short only says that time ran out, so its error
// does not replace that one.
func eventually(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	var last error
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		fnErr := fn(ctx)
		if fnErr != nil && ctx.Err() == nil {
			last = fnErr
		}
		return fnErr == nil, nil
	})
	if err != nil && last != nil {
		return fmt.Errorf("%w: %w", err, last)
	}
	return err
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
func (e *environment) createRouter(t *testing.T, namespace string, replicas int32) *nbv1alpha1.NetworkRouter {
	t.Helper()
	router, err := e.newRouter(t.Context(), namespace, replicas)
	require.NoError(t, err)
	return router
}

// startRouter creates a NetworkRouter like createRouter but does not wait for
// its routing peers.
func (e *environment) startRouter(t *testing.T, namespace string, replicas int32) *nbv1alpha1.NetworkRouter {
	t.Helper()
	router := routerFor(namespace, replicas)
	require.NoError(t, e.k8s.Create(t.Context(), router))
	return router
}

func (e *environment) newRouter(ctx context.Context, namespace string, replicas int32) (*nbv1alpha1.NetworkRouter, error) {
	router := routerFor(namespace, replicas)
	if err := e.k8s.Create(ctx, router); err != nil {
		return nil, err
	}
	return router, e.waitReadyCtx(ctx, router)
}

// routerFor builds a NetworkRouter in the fixture DNS zone. The operator names
// the router's NetBird network after the object alone, so the name is random to
// keep the tests' networks apart.
func routerFor(namespace string, replicas int32) *nbv1alpha1.NetworkRouter {
	return &nbv1alpha1.NetworkRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "router-" + rand.String(5),
			Namespace: namespace,
		},
		Spec: nbv1alpha1.NetworkRouterSpec{
			DNSZoneRef: nbv1alpha1.DNSZoneReference{Name: dnsZone},
			WorkloadOverride: &nbv1alpha1.WorkloadOverride{
				Replicas: &replicas,
			},
		},
	}
}

// createBackend deploys an HTTP server behind a ClusterIP Service of the same
// name and waits until it serves.
func (e *environment) createBackend(t *testing.T, namespace, name string) *corev1.Service {
	t.Helper()
	return e.createBackendOfType(t, namespace, name, corev1.ServiceTypeClusterIP)
}

// createBackendOfType is createBackend with a Service of the given type.
func (e *environment) createBackendOfType(t *testing.T, namespace, name string, serviceType corev1.ServiceType) *corev1.Service {
	t.Helper()
	svc, err := e.newBackendWith(t.Context(), namespace, name, serviceType, backendServicePort)
	require.NoError(t, err)
	return svc
}

// createBackendOnPort is createBackend with the Service exposing port.
func (e *environment) createBackendOnPort(t *testing.T, namespace, name string, port int32) *corev1.Service {
	t.Helper()
	svc, err := e.newBackendWith(t.Context(), namespace, name, corev1.ServiceTypeClusterIP, port)
	require.NoError(t, err)
	return svc
}

func (e *environment) newBackend(ctx context.Context, namespace, name string) (*corev1.Service, error) {
	return e.newBackendWith(ctx, namespace, name, corev1.ServiceTypeClusterIP, backendServicePort)
}

func (e *environment) newBackendWith(ctx context.Context, namespace, name string, serviceType corev1.ServiceType, port int32) (*corev1.Service, error) {
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
	if err := e.k8s.Create(ctx, dep); err != nil {
		return nil, err
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType,
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       port,
					TargetPort: intstr.FromInt32(backendPort),
				},
			},
		},
	}
	if err := e.k8s.Create(ctx, svc); err != nil {
		return nil, err
	}
	return svc, eventually(ctx, readyTimeout, func(ctx context.Context) error {
		return e.workloadCurrent(ctx, "Deployment", namespace, name)
	})
}

// touch changes an annotation to make the operator reconcile the object now.
// Most controllers otherwise only resync every 15 minutes, which is how long a
// change made behind the operator's back can go unnoticed.
func (e *environment) touch(t *testing.T, obj client.Object) {
	t.Helper()
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKeyFromObject(obj), obj))
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["e2e.netbird.io/touched"] = time.Now().Format(time.RFC3339Nano)
	obj.SetAnnotations(annotations)
	require.NoError(t, e.k8s.Update(t.Context(), obj))
}
