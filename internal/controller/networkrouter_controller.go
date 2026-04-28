package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdutil"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	policyv1ac "k8s.io/client-go/applyconfigurations/policy/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	nbv1alpha1ac "github.com/netbirdio/kubernetes-operator/pkg/applyconfigurations/api/v1alpha1"
)

type NetworkRouterReconciler struct {
	client.Client

	Netbird       *netbird.Client
	ManagementURL string
	ClientImage   string
}

// +kubebuilder:rbac:groups=netbird.io,resources=networkrouters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=networkrouters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=networkrouters/finalizers,verbs=update

// nolint:gocyclo
func (r *NetworkRouterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	netRouter := &nbv1alpha1.NetworkRouter{}
	err := r.Get(ctx, req.NamespacedName, netRouter)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(netRouter, r.Client)

	if !netRouter.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sp, netRouter)
	}

	ownerRef, err := k8sutil.ControllerReference(netRouter, r.Scheme())
	if err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the DNS Zone exists.
	_, err = netbirdutil.GetDNSZoneByName(ctx, r.Netbird, netRouter.Spec.DNSZoneRef.Name)
	if err != nil {
		return ctrl.Result{}, err
	}

	controllerutil.AddFinalizer(netRouter, k8sutil.Finalizer("networkrouter"))

	networkID, err := func() (string, error) {
		networkReq := api.NetworkRequest{
			Name: netRouter.Name,
		}
		if netRouter.Status.NetworkID != "" {
			networkResp, err := r.Netbird.Networks.Update(ctx, netRouter.Status.NetworkID, networkReq)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				return networkResp.Id, nil
			}
		}
		networkResp, err := r.Netbird.Networks.Create(ctx, networkReq)
		if err != nil {
			return "", err
		}
		return networkResp.Id, nil
	}()
	if err != nil {
		return ctrl.Result{}, err
	}
	netRouter.Status.NetworkID = networkID
	err = sp.Patch(ctx, netRouter)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Calculate unique suffix used for Netbird resources.
	sum := sha256.Sum256([]byte(netRouter.UID))
	uniqueSuffix := networkID + "-" + fmt.Sprintf("%x", sum[:4])[:8]

	// Create the group used by the router to discover peers.
	groupAC := nbv1alpha1ac.Group(fmt.Sprintf("networkrouter-%s", netRouter.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithSpec(
			nbv1alpha1ac.GroupSpec().
				WithName(fmt.Sprintf("networkrouter-%s", uniqueSuffix)),
		)
	err = r.Client.Apply(ctx, groupAC)
	if err != nil {
		return ctrl.Result{}, err
	}
	group := &nbv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *groupAC.Name,
			Namespace: *groupAC.Namespace,
		},
	}
	err = r.Client.Get(ctx, client.ObjectKeyFromObject(group), group)
	if err != nil {
		return ctrl.Result{}, err
	}
	if group.Status.GroupID == "" {
		return ctrl.Result{}, nil
	}

	// Create the setup key used by routing peers.
	setupKeyAC := nbv1alpha1ac.SetupKey(fmt.Sprintf("networkrouter-%s", netRouter.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithSpec(
			nbv1alpha1ac.SetupKeySpec().
				WithName(fmt.Sprintf("networkrouter-%s", uniqueSuffix)).
				WithEphemeral(true).
				WithAutoGroups(nbv1alpha1ac.GroupReference().WithID(group.Status.GroupID)),
		)
	err = r.Client.Apply(ctx, setupKeyAC)
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
		return ctrl.Result{}, err
	}
	if setupKey.Status.SetupKeyID == "" {
		return ctrl.Result{}, nil
	}

	// Create the routing peer in netbird.
	routingPeerID, err := func() (string, error) {
		routerReq := api.NetworkRouterRequest{
			Enabled:    true,
			Masquerade: true,
			Metric:     9999,
			PeerGroups: ptr.To([]string{group.Status.GroupID}),
		}
		if netRouter.Status.RoutingPeerID != "" {
			resp, err := r.Netbird.Networks.Routers(networkID).Update(ctx, netRouter.Status.RoutingPeerID, routerReq)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				return resp.Id, nil
			}
		}
		resp, err := r.Netbird.Networks.Routers(networkID).Create(ctx, routerReq)
		if err != nil {
			return "", err
		}
		return resp.Id, nil
	}()
	if err != nil {
		return ctrl.Result{}, err
	}
	netRouter.Status.RoutingPeerID = routingPeerID
	err = sp.Patch(ctx, netRouter, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}

	// Create the deployment.
	selectorLabels := map[string]string{
		"app.kubernetes.io/name":     "networkrouter",
		"app.kubernetes.io/instance": req.Name,
	}

	logLevel := "info"
	if netRouter.Spec.LogLevel != "" {
		logLevel = netRouter.Spec.LogLevel
	}

	clientImage := r.ClientImage
	if netRouter.Spec.Image != "" {
		clientImage = netRouter.Spec.Image
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
			WithContainers(corev1ac.Container().
				WithName("netbird").
				WithImage(clientImage).
				WithEnv(
					corev1ac.EnvVar().
						WithName("NB_SETUP_KEY").
						WithValueFrom(corev1ac.EnvVarSource().
							WithSecretKeyRef(corev1ac.SecretKeySelector().
								WithName(setupKey.SecretName()).
								WithKey(SetupKeySecretKey),
							),
						),
					corev1ac.EnvVar().
						WithName("NB_MANAGEMENT_URL").
						WithValue(r.ManagementURL),
					corev1ac.EnvVar().
						WithName("NB_LOG_LEVEL").
						WithValue(logLevel),
					corev1ac.EnvVar().
						WithName("NB_LOG_FILE").
						WithValue("console"),
					corev1ac.EnvVar().
						WithName("NB_ENTRYPOINT_SERVICE_TIMEOUT").
						WithValue("0"),
				).
				WithStartupProbe(corev1ac.Probe().WithExec(corev1ac.ExecAction().WithCommand("netbird", "status", "--check", "startup"))).
				WithReadinessProbe(corev1ac.Probe().WithExec(corev1ac.ExecAction().WithCommand("netbird", "status", "--check", "ready"))).
				WithSecurityContext(corev1ac.SecurityContext().
					WithCapabilities(corev1ac.Capabilities().
						WithAdd("NET_ADMIN").
						WithAdd("SYS_RESOURCE").
						WithAdd("SYS_ADMIN"),
					).
					WithPrivileged(true),
				).
				WithResources(corev1ac.ResourceRequirements().
					WithRequests(corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					}),
				),
			),
		)

	workloadLabels := map[string]string{}
	workloadAnnotations := map[string]string{}
	replicas := int32(3)
	if netRouter.Spec.WorkloadOverride != nil {
		if netRouter.Spec.WorkloadOverride.Labels != nil {
			workloadLabels = netRouter.Spec.WorkloadOverride.Labels
		}
		if netRouter.Spec.WorkloadOverride.Annotations != nil {
			workloadAnnotations = netRouter.Spec.WorkloadOverride.Annotations
		}
		if netRouter.Spec.WorkloadOverride.Replicas != nil {
			replicas = *netRouter.Spec.WorkloadOverride.Replicas
		}
		if netRouter.Spec.WorkloadOverride.PodTemplate != nil {
			baseJSON, err := json.Marshal(&podTemplateSpecAC)
			if err != nil {
				return ctrl.Result{}, err
			}
			overrideJSON, err := json.Marshal(netRouter.Spec.WorkloadOverride.PodTemplate)
			if err != nil {
				return ctrl.Result{}, err
			}
			mergedJSON, err := strategicpatch.StrategicMergePatch(baseJSON, overrideJSON, corev1.PodTemplateSpec{})
			if err != nil {
				return ctrl.Result{}, err
			}
			err = json.Unmarshal(mergedJSON, &podTemplateSpecAC)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	maps.Copy(workloadLabels, selectorLabels)

	depAC := appsv1ac.Deployment(fmt.Sprintf("networkrouter-%s", req.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithLabels(workloadLabels).
		WithAnnotations(workloadAnnotations).
		WithSpec(appsv1ac.DeploymentSpec().WithReplicas(replicas).WithSelector(metav1ac.LabelSelector().WithMatchLabels(selectorLabels)).WithTemplate(podTemplateSpecAC))
	err = r.Client.Apply(ctx, depAC)
	if err != nil {
		return ctrl.Result{}, err
	}

	if replicas > 1 {
		pdbAC := policyv1ac.PodDisruptionBudget(fmt.Sprintf("networkrouter-%s", req.Name), req.Namespace).
			WithOwnerReferences(ownerRef).
			WithLabels(workloadLabels).
			WithAnnotations(workloadAnnotations).
			WithSpec(policyv1ac.PodDisruptionBudgetSpec().
				WithMaxUnavailable(intstr.FromInt(1)).
				WithSelector(metav1ac.LabelSelector().
					WithMatchLabels(selectorLabels),
				),
			)
		err = r.Client.Apply(ctx, pdbAC)
		if err != nil {
			return ctrl.Result{}, err
		}
	} else {
		pdb := policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("networkrouter-%s", req.Name),
				Namespace: req.Namespace,
			},
		}
		err = r.Client.Delete(ctx, &pdb)
		if err != nil && !kerrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *depAC.Name,
			Namespace: *depAC.Namespace,
		},
	}
	err = r.Client.Get(ctx, client.ObjectKeyFromObject(dep), dep)
	if err != nil {
		return ctrl.Result{}, err
	}
	if dep.Status.ReadyReplicas != dep.Status.Replicas {
		return ctrl.Result{}, nil
	}

	conditions.MarkTrue(netRouter, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	err = sp.Patch(ctx, netRouter, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 15 * time.Minute}, nil
}

func (r *NetworkRouterReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, netRouter *nbv1alpha1.NetworkRouter) (ctrl.Result, error) {
	if netRouter.Status.RoutingPeerID != "" {
		err := r.Netbird.Networks.Routers(netRouter.Status.NetworkID).Delete(ctx, netRouter.Status.RoutingPeerID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	if netRouter.Status.NetworkID != "" {
		err := r.Netbird.Networks.Delete(ctx, netRouter.Status.NetworkID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	controllerutil.RemoveFinalizer(netRouter, k8sutil.Finalizer("networkrouter"))
	err := sp.Patch(ctx, netRouter)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NetworkRouterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.NetworkRouter{}).
		Owns(&nbv1alpha1.Group{}).
		Owns(&nbv1alpha1.SetupKey{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
