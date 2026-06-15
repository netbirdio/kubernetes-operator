// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
	"github.com/netbirdio/kubernetes-operator/internal/version"
	nbv1alpha1ac "github.com/netbirdio/kubernetes-operator/pkg/applyconfigurations/api/v1alpha1"
)

// ClusterProxyReconciler reconciles a ClusterProxy object
type ClusterProxyReconciler struct {
	client.Client

	ApiKey        string
	ManagementURL string
}

// +kubebuilder:rbac:groups=netbird.io,resources=clusterproxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=clusterproxies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=clusterproxies/finalizers,verbs=update

func (r *ClusterProxyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusterProxy := &nbv1alpha1.ClusterProxy{}
	err := r.Get(ctx, req.NamespacedName, clusterProxy)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(clusterProxy, r.Client)

	if !clusterProxy.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	ownerRef, err := k8sutil.ControllerReference(clusterProxy, r.Scheme())
	if err != nil {
		return ctrl.Result{}, err
	}

	// Calculate unique suffix used for Netbird resources.
	sum := sha256.Sum256([]byte(clusterProxy.UID))
	uniqueSuffix := fmt.Sprintf("%x", sum[:4])[:8]

	// Create the setup key used by routing peers.
	setupKeyAC := nbv1alpha1ac.SetupKey(fmt.Sprintf("clusterproxy-%s", clusterProxy.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithSpec(
			nbv1alpha1ac.SetupKeySpec().
				WithName(fmt.Sprintf("clusterproxy-%s", uniqueSuffix)).
				WithEphemeral(true).
				WithAllowExtraDnsLabels(true),
		)
	err = r.Client.Apply(ctx, setupKeyAC, client.ForceOwnership)
	if err != nil {
		return ctrl.Result{}, err
	}
	setupKey := nbv1alpha1.SetupKey{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *setupKeyAC.Name,
			Namespace: *setupKeyAC.Namespace,
		},
	}
	err = r.Get(ctx, client.ObjectKeyFromObject(&setupKey), &setupKey)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if setupKey.Status.SetupKeyID == "" {
		return ctrl.Result{}, nil
	}

	// Create secret for api token.
	secretAC := corev1ac.Secret(fmt.Sprintf("clusterproxy-%s", req.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithStringData(map[string]string{"api-key": r.ApiKey})
	err = r.Client.Apply(ctx, secretAC, client.ForceOwnership)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Create the API proxy deployment.
	selectorLabels := map[string]string{
		"app.kubernetes.io/name":     "clusterproxy",
		"app.kubernetes.io/instance": req.Name,
	}
	podTemplateSpecAC := corev1ac.PodTemplateSpec().
		WithLabels(selectorLabels).
		WithSpec(corev1ac.PodSpec().
			WithTopologySpreadConstraints(
				corev1ac.TopologySpreadConstraint().
					WithMaxSkew(1).
					WithTopologyKey(corev1.LabelHostname).
					WithWhenUnsatisfiable(corev1.ScheduleAnyway).
					WithLabelSelector(metav1ac.LabelSelector().
						WithMatchLabels(selectorLabels),
					),
			).
			WithServiceAccountName(clusterProxy.Spec.ServiceAccountName).
			WithContainers(corev1ac.Container().
				WithName("proxy").
				WithImage(version.KubeApiProxyImage).
				WithArgs(
					"--setup-key",
					"$(SETUP_KEY)",
					"--api-key",
					"$(API_KEY)",
					"--instance-name",
					"$(POD_NAME)",
					"--cluster-name",
					clusterProxy.Spec.ClusterName,
					"--kubernetes-api-server",
					clusterProxy.Spec.APIServer,
					"--management-url",
					r.ManagementURL,
				).
				WithEnv(
					corev1ac.EnvVar().
						WithName("POD_NAME").
						WithValueFrom(corev1ac.EnvVarSource().
							WithFieldRef(corev1ac.ObjectFieldSelector().WithFieldPath("metadata.name")),
						),
					corev1ac.EnvVar().
						WithName("SETUP_KEY").
						WithValueFrom(corev1ac.EnvVarSource().
							WithSecretKeyRef(corev1ac.SecretKeySelector().
								WithName(setupKey.SecretName()).
								WithKey(SetupKeySecretKey),
							),
						),
					corev1ac.EnvVar().
						WithName("API_KEY").
						WithValueFrom(corev1ac.EnvVarSource().
							WithSecretKeyRef(corev1ac.SecretKeySelector().
								WithName(*secretAC.Name).
								WithKey("api-key"),
							),
						),
				).
				WithSecurityContext(corev1ac.SecurityContext().
					WithAllowPrivilegeEscalation(false).
					WithReadOnlyRootFilesystem(true).
					WithRunAsNonRoot(true).
					WithCapabilities(corev1ac.Capabilities().WithDrop("ALL")),
				).
				WithResources(corev1ac.ResourceRequirements().
					WithRequests(corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					}),
				),
			),
		)

	depAC := appsv1ac.Deployment(fmt.Sprintf("clusterproxy-%s", req.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithLabels(selectorLabels).
		WithSpec(appsv1ac.DeploymentSpec().WithReplicas(1).WithSelector(metav1ac.LabelSelector().WithMatchLabels(selectorLabels)).WithTemplate(podTemplateSpecAC))
	err = r.Client.Apply(ctx, depAC, client.ForceOwnership)
	if err != nil {
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(clusterProxy, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	err = sp.Patch(ctx, clusterProxy, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *ClusterProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.ClusterProxy{}).
		Owns(&nbv1alpha1.SetupKey{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
