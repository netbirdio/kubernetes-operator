/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

const (
	setupKeyAnnotation = "netbird.io/setup-key"
)

// nolint:unused
// log is for logging in this package.
var podlog = logf.Log.WithName("pod-resource")

// SetupPodWebhookWithManager registers the webhook for Pod in the manager.
func SetupPodWebhookWithManager(mgr ctrl.Manager, managementURL, clientImage string) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Pod{}).
		WithDefaulter(&PodNetbirdInjector{
			client:        mgr.GetClient(),
			managementURL: managementURL,
			clientImage:   clientImage,
		}).
		Complete()
}

// PodNetbirdInjector struct is responsible for setting default values on the custom resource of the
// Kind Pod when those are created or updated.
type PodNetbirdInjector struct {
	client        client.Client
	managementURL string
	clientImage   string
}

var _ webhook.CustomDefaulter = &PodNetbirdInjector{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Pod.
func (d *PodNetbirdInjector) Default(ctx context.Context, obj runtime.Object) error {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return fmt.Errorf("expected a Pod object but got %T", obj)
	}
	podlog.Info("Defaulting for Pod", "name", pod.GetName())

	// if the setup key annotation is missing, do nothing.
	if pod.Annotations == nil || pod.Annotations[setupKeyAnnotation] == "" {
		return nil
	}

	// retrieve the NBSetupKey resource
	var nbSetupKey netbirdiov1.NBSetupKey
	err := d.client.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: pod.Annotations[setupKeyAnnotation]}, &nbSetupKey)
	if err != nil {
		return err
	}

	// ensure the NBSetupKey is ready.
	ready := false
	for _, c := range nbSetupKey.Status.Conditions {
		if c.Type == netbirdiov1.NBSetupKeyReady {
			ready = c.Status == corev1.ConditionTrue
		}
	}
	if !ready {
		return fmt.Errorf("NBSetupKey is not ready")
	}

	managementURL := d.managementURL
	if nbSetupKey.Spec.ManagementURL != "" {
		managementURL = nbSetupKey.Spec.ManagementURL
	}

	// build the base arguments.
	args := []string{
		"--setup-key-file", "/etc/nbkey",
		"-m", managementURL,
	}

	// check for extra DNS labels in annotations.
	if pod.Annotations != nil {
		if extra, ok := pod.Annotations["netbird.io/extra-dns-labels"]; ok && extra != "" {
			podlog.Info("Found extra DNS labels", "extra", extra)
			// append extra DNS labels to the CLI args.
			args = append(args, "--extra-dns-labels", extra)
		}
	}

	// Append the netbird container with the constructed args.
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:  "netbird",
		Image: d.clientImage,
		Args:  args,
		Env: []corev1.EnvVar{
			{
				Name: "NB_SETUP_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &nbSetupKey.Spec.SecretKeyRef,
				},
			},
			{
				Name:  "NB_MANAGEMENT_URL",
				Value: managementURL,
			},
		},
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		},
	})

	return nil
}
