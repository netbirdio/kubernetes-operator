// SPDX-License-Identifier: BSD-3-Clause

package v1

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/controller"
)

const (
	SidecarProfileAnnotation = "netbird.io/sidecar-profile"

	setupKeyAnnotation = "netbird.io/setup-key"
	sidecarAnnotation  = "netbird.io/init-sidecar"
)

// nolint:unused
// log is for logging in this package.
var podlog = logf.Log.WithName("pod-resource")

// SetupPodWebhookWithManager registers the webhook for Pod in the manager.
func SetupPodWebhookWithManager(mgr ctrl.Manager, managementURL, clientImage string) error {
	return ctrl.NewWebhookManagedBy(mgr, &corev1.Pod{}).
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

var _ admission.Defaulter[*corev1.Pod] = &PodNetbirdInjector{}

func (d *PodNetbirdInjector) Default(ctx context.Context, pod *corev1.Pod) error {
	// If setup key annotations are set we do the legacy injection.
	if pod.Annotations != nil && pod.Annotations[setupKeyAnnotation] != "" {
		return d.legacyInjector(ctx, pod)
	}

	// Find sidecar profiles matching pods labels.
	sidecarProfileList := &nbv1alpha1.SidecarProfileList{}
	err := d.client.List(ctx, sidecarProfileList, client.InNamespace(pod.Namespace))
	if err != nil {
		return err
	}
	sidecarProfiles := []nbv1alpha1.SidecarProfile{}
	for _, sidecarProfile := range sidecarProfileList.Items {
		if sidecarProfile.Spec.PodSelector == nil || sidecarProfile.Spec.PodSelector.Size() == 0 {
			sidecarProfiles = append(sidecarProfiles, sidecarProfile)
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(sidecarProfile.Spec.PodSelector)
		if err != nil {
			return err
		}
		if selector.Matches(labels.Set(pod.Labels)) {
			sidecarProfiles = append(sidecarProfiles, sidecarProfile)
		}
	}
	// Do nothing if no profile matches.
	if len(sidecarProfiles) == 0 {
		return nil
	}
	// If two match we chose the first in alphabetical order.
	if len(sidecarProfiles) > 1 {
		slices.SortFunc(sidecarProfiles, func(a, b nbv1alpha1.SidecarProfile) int {
			return cmp.Compare(a.Name, b.Name)
		})
	}
	sidecarProfile := sidecarProfiles[0]

	// Get setup key referenced by sidecar profile.
	setupKey := &nbv1alpha1.SetupKey{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sidecarProfile.Spec.SetupKeyRef.Name,
			Namespace: pod.Namespace,
		},
	}
	err = d.client.Get(ctx, client.ObjectKeyFromObject(setupKey), setupKey)
	if err != nil {
		return err
	}

	// Add sidecar container.
	envVars := []corev1.EnvVar{
		{
			Name: "NB_SETUP_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: setupKey.SecretName(),
					},
					Key: controller.SetupKeySecretKey,
				},
			},
		},
		{
			Name:  "NB_MANAGEMENT_URL",
			Value: d.managementURL,
		},
		{
			Name:  "NB_LOG_FILE",
			Value: "console",
		},
		{
			Name:  "NB_DISABLE_PROFILES",
			Value: "true",
		},
		{
			Name:  "NB_DAEMON_ADDR",
			Value: "unix:///var/run/netbird/netbird.sock",
		},
		{
			Name:  "NB_ENTRYPOINT_SERVICE_TIMEOUT",
			Value: "0",
		},
	}
	if len(sidecarProfile.Spec.ExtraDNSLabels) > 0 {
		envVars = append(envVars, corev1.EnvVar{
			Name:  "NB_EXTRA_DNS_LABELS",
			Value: strings.Join(sidecarProfile.Spec.ExtraDNSLabels, ","),
		})
	}

	container := corev1.Container{
		Name:  "netbird",
		Image: d.clientImage,
		Env:   envVars,
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem: new(true),
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{
					"NET_ADMIN",
					"SYS_RESOURCE",
					"SYS_ADMIN",
				},
			},
			Privileged: new(true),
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "netbird-run",
				MountPath: "/var/run/netbird",
			},
			{
				Name:      "netbird-lib",
				MountPath: "/var/lib/netbird",
			},
			{
				Name:      "ssh-etc",
				MountPath: "/etc/ssh",
			},
			{
				Name:      "resolv-conf",
				MountPath: "/etc/resolv.conf",
				SubPath:   "resolv.conf",
			},
			{
				Name:      "resolv-conf",
				MountPath: "/etc/resolv.conf.original.netbird",
				SubPath:   "resolv.conf.original.netbird",
			},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
		},
	}
	if sidecarProfile.Spec.ContainerOverride != nil {
		baseJSON, err := json.Marshal(&container)
		if err != nil {
			return err
		}
		overrideJSON, err := json.Marshal(sidecarProfile.Spec.ContainerOverride)
		if err != nil {
			return err
		}
		mergedJSON, err := strategicpatch.StrategicMergePatch(baseJSON, overrideJSON, corev1.Container{})
		if err != nil {
			return err
		}
		err = json.Unmarshal(mergedJSON, &container)
		if err != nil {
			return err
		}
	}

	volumes := []corev1.Volume{
		{
			Name: "netbird-run",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "netbird-lib",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "ssh-etc",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "resolv-conf",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, volumes...)

	switch sidecarProfile.Spec.InjectionMode {
	case nbv1alpha1.InjectionModeSidecar:
		container.RestartPolicy = new(corev1.ContainerRestartPolicyAlways)
		pod.Spec.InitContainers = slices.Insert(pod.Spec.InitContainers, 0, container)
	case nbv1alpha1.InjectionModeContainer:
		pod.Spec.Containers = slices.Insert(pod.Spec.Containers, 0, container)
	default:
		return fmt.Errorf("unknown injection mode %s", sidecarProfile.Spec.InjectionMode)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[SidecarProfileAnnotation] = sidecarProfile.Name

	resolvInitContainer := corev1.Container{
		Name:    "resolv-conf",
		Image:   d.clientImage,
		Command: []string{"sh", "-c", "cp /etc/resolv.conf /tmp/resolv.conf && cp /etc/resolv.conf /tmp/resolv.conf.original.netbird"},
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem: new(true),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "resolv-conf",
				MountPath: "/tmp",
			},
		},
	}
	pod.Spec.InitContainers = slices.Insert(pod.Spec.InitContainers, 0, resolvInitContainer)

	return nil
}

func (d *PodNetbirdInjector) legacyInjector(ctx context.Context, pod *corev1.Pod) error {
	podlog.Info("Defaulting for Pod", "name", pod.GetName())

	// retrieve the NBSetupKey resource
	var nbSetupKey nbv1.NBSetupKey
	err := d.client.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: pod.Annotations[setupKeyAnnotation]}, &nbSetupKey)
	if err != nil {
		return err
	}

	// ensure the NBSetupKey is ready.
	ready := false
	for _, c := range nbSetupKey.Status.Conditions {
		if c.Type == nbv1.NBSetupKeyReady {
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

	// build environment variables
	envVars := []corev1.EnvVar{
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
	}

	// check for extra DNS labels in annotations and add as environment variable
	if pod.Annotations != nil {
		if extra, ok := pod.Annotations["netbird.io/extra-dns-labels"]; ok && extra != "" {
			podlog.Info("Found extra DNS labels", "extra", extra)
			envVars = append(envVars, corev1.EnvVar{
				Name:  "NB_EXTRA_DNS_LABELS",
				Value: extra,
			})
		}
	}

	// Build the netbird container spec.
	nbContainer := corev1.Container{
		Name:  "netbird",
		Image: d.clientImage,
		Env:   envVars,
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		},
		VolumeMounts: nbSetupKey.Spec.VolumeMounts,
	}

	// If sidecar mode is requested, inject as a sidecar (init container with restartPolicy: Always).
	if pod.Annotations[sidecarAnnotation] == "true" {
		restartPolicy := corev1.ContainerRestartPolicyAlways
		nbContainer.RestartPolicy = &restartPolicy
		pod.Spec.InitContainers = append(pod.Spec.InitContainers, nbContainer)
	} else {
		pod.Spec.Containers = append(pod.Spec.Containers, nbContainer)
	}

	pod.Spec.Volumes = append(pod.Spec.Volumes, nbSetupKey.Spec.Volumes...)
	return nil
}
