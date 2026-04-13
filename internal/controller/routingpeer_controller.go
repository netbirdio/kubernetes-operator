package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/ssautil"
	nbv1alpha1ac "github.com/netbirdio/kubernetes-operator/pkg/applyconfigurations/api/v1alpha1"
)

const (
	RoutingPeerFinalizer = "netbird.io/routingpeer"
)

// RoutingPeerReconciler reconciles a RoutingPeer object
type RoutingPeerReconciler struct {
	client.Client

	Netbird       *netbird.Client
	ClientImage   string
	ManagementURL string
}

// +kubebuilder:rbac:groups=netbird.io,resources=routingpeers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=routingpeers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=routingpeers/finalizers,verbs=update
func (r *RoutingPeerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	routingPeer := nbv1alpha1.RoutingPeer{}
	err := r.Get(ctx, req.NamespacedName, &routingPeer)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !routingPeer.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, routingPeer)
	}

	ownerRef, err := ssautil.OwnerReference(&routingPeer, r.Scheme())
	if err != nil {
		return ctrl.Result{}, err
	}

	// Get network.
	networkID, err := func() (string, error) {
		network, err := r.Netbird.Networks.Get(ctx, *routingPeer.Spec.NetworkRef.ID)
		if err != nil {
			return "", err
		}
		return network.Id, nil
	}()
	if err != nil {
		return ctrl.Result{}, err
	}

	// Calculate unique suffix for routing peer deployment.
	sum := sha256.Sum256([]byte(routingPeer.UID))
	uniqueSuffix := networkID + "-" + fmt.Sprintf("%x", sum[:4])[:8]

	// Add finalizer.
	if controllerutil.AddFinalizer(&routingPeer, RoutingPeerFinalizer) {
		err := r.Client.Update(ctx, &routingPeer)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// Create the group used by the router to discover peers.
	groupAC := nbv1alpha1ac.Group(fmt.Sprintf("routingpeer-%s", routingPeer.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithSpec(
			nbv1alpha1ac.GroupSpec().
				WithName(fmt.Sprintf("routingpeer-%s", uniqueSuffix)),
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
	if group.Status.GroupID == nil {
		return ctrl.Result{}, nil
	}
	peerGroups := []string{*group.Status.GroupID}

	// Create the setup key used by routing peers.
	setupKeyAC := nbv1alpha1ac.SetupKey(fmt.Sprintf("routingpeer-%s", routingPeer.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithSpec(
			nbv1alpha1ac.SetupKeySpec().
				WithName(fmt.Sprintf("routingpeer-%s", uniqueSuffix)).
				WithEphemeral(true).
				WithAutoGroups(nbv1alpha1ac.ResourceReference().WithID(*group.Status.GroupID)),
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
	if setupKey.Status.SetupKeyID == nil {
		return ctrl.Result{}, nil
	}

	// Create the routing peer in netbird.
	routingPeerID, err := func() (string, error) {
		if routingPeer.Status.RoutingPeerID != nil {
			routerReq := api.NetworkRouterRequest{
				Enabled:    true,
				Masquerade: true,
				Metric:     9999,
				PeerGroups: &peerGroups,
			}
			resp, err := r.Netbird.Networks.Routers(networkID).Update(ctx, *routingPeer.Status.RoutingPeerID, routerReq)
			if err == nil {
				return resp.Id, nil
			}
			if !netbird.IsNotFound(err) {
				return "", err
			}
		}

		routerReq := api.NetworkRouterRequest{
			Enabled:    true,
			Masquerade: true,
			Metric:     9999,
			PeerGroups: &peerGroups,
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
	routingPeerAC := nbv1alpha1ac.RoutingPeer(req.Name, req.Namespace).
		WithStatus(nbv1alpha1ac.RoutingPeerStatus().WithRoutingPeerID(routingPeerID).WithNetworkID(networkID))
	err = r.Client.Status().Apply(ctx, routingPeerAC)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Create the deployment.
	podTemplateSpecAC := corev1ac.PodTemplateSpec().
		WithLabels(map[string]string{
			"foo": "bar",
		}).
		WithSpec(corev1ac.PodSpec().
			WithContainers(corev1ac.Container().
				WithName("netbird").
				WithImage(r.ClientImage).
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
						WithValue("info"),
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
				),
			),
		)
	replicas := int32(3)
	if routingPeer.Spec.DeploymentOverride != nil {
		if routingPeer.Spec.DeploymentOverride.Replicas != nil {
			replicas = *routingPeer.Spec.DeploymentOverride.Replicas
		}
		if routingPeer.Spec.DeploymentOverride.PodTemplate != nil {
			baseJSON, err := json.Marshal(&podTemplateSpecAC)
			if err != nil {
				return ctrl.Result{}, err
			}
			overrideJSON, err := json.Marshal(routingPeer.Spec.DeploymentOverride.PodTemplate)
			if err != nil {
				return ctrl.Result{}, err
			}
			mergedJSON, err := strategicpatch.StrategicMergePatch(baseJSON, overrideJSON, corev1.PodTemplate{})
			if err != nil {
				return ctrl.Result{}, err
			}
			err = json.Unmarshal(mergedJSON, &podTemplateSpecAC)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	depAC := appsv1ac.Deployment(fmt.Sprintf("routingpeer-%s", req.Name), req.Namespace).
		WithOwnerReferences(ownerRef).
		WithSpec(appsv1ac.DeploymentSpec().WithReplicas(replicas).WithSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"foo": "bar"})).WithTemplate(podTemplateSpecAC))
	err = r.Client.Apply(ctx, depAC)
	if err != nil {
		return ctrl.Result{}, err
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

	return ctrl.Result{RequeueAfter: 15 * time.Minute}, nil
}

func (r *RoutingPeerReconciler) reconcileDelete(ctx context.Context, routingPeer nbv1alpha1.RoutingPeer) (ctrl.Result, error) {
	if routingPeer.Status.NetworkID != nil && routingPeer.Status.RoutingPeerID != nil {
		err := r.Netbird.Networks.Routers(*routingPeer.Status.NetworkID).Delete(ctx, *routingPeer.Status.RoutingPeerID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	if controllerutil.RemoveFinalizer(&routingPeer, RoutingPeerFinalizer) {
		err := r.Client.Update(ctx, &routingPeer)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoutingPeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.RoutingPeer{}).
		Owns(&nbv1alpha1.Group{}).
		Owns(&nbv1alpha1.SetupKey{}).
		Owns(&appsv1.Deployment{}).
		// TODO: watch referenced networks.
		Complete(r)
}
