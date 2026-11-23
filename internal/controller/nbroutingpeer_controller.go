// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
)

// NBRoutingPeerReconciler reconciles a NBRoutingPeer object
type NBRoutingPeerReconciler struct {
	client.Client

	Netbird            *netbird.Client
	ClientImage        string
	ClusterName        string
	ManagementURL      string
	NamespacedNetworks bool
	DefaultLabels      map[string]string
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NBRoutingPeerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	logger := ctrl.Log.WithName("NBRoutingPeer").WithValues("namespace", req.Namespace, "name", req.Name)
	logger.Info("Reconciling NBRoutingPeer")

	nbrp := &nbv1.NBRoutingPeer{}
	err = r.Get(ctx, req.NamespacedName, nbrp)
	if err != nil {
		if !errors.IsNotFound(err) {
			logger.Error(errKubernetesAPI, "error getting NBRoutingPeer", "err", err)
		}
		return ctrl.Result{RequeueAfter: defaultRequeueAfter}, nil
	}

	originalNBRP := nbrp.DeepCopy()
	defer func() {
		if originalNBRP.DeletionTimestamp != nil && len(nbrp.Finalizers) == 0 {
			return
		}
		if !originalNBRP.Status.Equal(nbrp.Status) {
			err = r.Client.Status().Update(ctx, nbrp)
			if err != nil {
				logger.Error(errKubernetesAPI, "error updating NBRoutingPeer Status", "err", err)
			}
		}
		if err != nil {
			// double check result is nil, otherwise error is not printed
			// and exponential backoff doesn't work properly
			res = ctrl.Result{}
			return
		}
		if !res.Requeue && res.RequeueAfter == 0 {
			res.RequeueAfter = defaultRequeueAfter
		}
	}()

	if nbrp.DeletionTimestamp != nil {
		if len(nbrp.Finalizers) == 0 {
			return ctrl.Result{}, nil
		}
		return r.handleDelete(ctx, req, nbrp, logger)
	}

	logger.Info("NBRoutingPeer: Checking network")
	err = r.handleNetwork(ctx, req, nbrp, logger)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("NBRoutingPeer: Checking groups")
	nbGroup, result, err := r.handleGroup(ctx, req, nbrp, logger)
	if nbGroup == nil {
		return *result, err
	}

	logger.Info("NBRoutingPeer: Checking setup keys")
	result, err = r.handleSetupKey(ctx, req, nbrp, *nbGroup, logger)
	if result != nil {
		return *result, err
	}

	logger.Info("NBRoutingPeer: Checking network router")
	err = r.handleRouter(ctx, nbrp, *nbGroup, logger)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("NBRoutingPeer: Checking deployment")
	err = r.handleDeployment(ctx, req, nbrp, logger)
	if err != nil {
		return ctrl.Result{}, err
	}

	nbrp.Status.Conditions = nbv1.NBConditionTrue()
	return ctrl.Result{}, nil
}

// handleDeployment reconcile routing peer Deployment
func (r *NBRoutingPeerReconciler) handleDeployment(ctx context.Context, req ctrl.Request, nbrp *nbv1.NBRoutingPeer, logger logr.Logger) error {
	routingPeerDeployment := appsv1.Deployment{}
	err := r.Client.Get(ctx, req.NamespacedName, &routingPeerDeployment)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting Deployment", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error getting Deployment: %v", err))
		return err
	}

	labels := r.DefaultLabels
	maps.Copy(labels, nbrp.Spec.Labels)
	podLabels := labels
	podLabels["app.kubernetes.io/name"] = "netbird-router"

	// Create deployment
	if errors.IsNotFound(err) {
		var replicas int32 = 3
		if nbrp.Spec.Replicas != nil {
			replicas = *nbrp.Spec.Replicas
		}
		routingPeerDeployment = appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nbrp.Name,
				Namespace: nbrp.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         nbv1.GroupVersion.Identifier(),
						Kind:               "NBRoutingPeer",
						Name:               nbrp.Name,
						UID:                nbrp.UID,
						BlockOwnerDeletion: new(true),
					},
				},
				Labels:      labels,
				Annotations: nbrp.Spec.Annotations,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/name": "netbird-router",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: podLabels,
					},
					Spec: corev1.PodSpec{
						NodeSelector: nbrp.Spec.NodeSelector,
						Tolerations:  nbrp.Spec.Tolerations,
						Containers: []corev1.Container{
							{
								Name:  "netbird",
								Image: r.ClientImage,
								Env: []corev1.EnvVar{
									{
										Name: "NB_SETUP_KEY",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: nbrp.Name,
												},
												Key: "setupKey",
											},
										},
									},
									{
										Name:  "NB_MANAGEMENT_URL",
										Value: r.ManagementURL,
									},
								},
								SecurityContext: r.buildSecurityContext(nbrp),
								Resources:       nbrp.Spec.Resources,
								VolumeMounts:    nbrp.Spec.VolumeMounts,
								StartupProbe:    routingPeerStartupProbe(),
								ReadinessProbe:  routingPeerReadinessProbe(),
								LivenessProbe:   routingPeerLivenessProbe(),
							},
						},
						Volumes: nbrp.Spec.Volumes,
					},
				},
			},
		}

		err = r.Client.Create(ctx, &routingPeerDeployment)
		if err != nil {
			logger.Error(errKubernetesAPI, "error creating Deployment", "err", err)
			nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error creating Deployment: %v", err))
			return err
		}
	} else if err == nil {
		updatedDeployment := routingPeerDeployment.DeepCopy()
		updatedDeployment.ObjectMeta.Name = nbrp.Name
		updatedDeployment.ObjectMeta.Namespace = nbrp.Namespace
		updatedDeployment.ObjectMeta.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion:         nbv1.GroupVersion.Identifier(),
				Kind:               "NBRoutingPeer",
				Name:               nbrp.Name,
				UID:                nbrp.UID,
				BlockOwnerDeletion: new(true),
			},
		}
		updatedDeployment.ObjectMeta.Labels = labels
		for k, v := range nbrp.Spec.Annotations {
			updatedDeployment.ObjectMeta.Annotations[k] = nbrp.Spec.Annotations[v]
		}
		var replicas int32 = 3
		if nbrp.Spec.Replicas != nil {
			replicas = *nbrp.Spec.Replicas
		}
		updatedDeployment.Spec.Replicas = &replicas
		updatedDeployment.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app.kubernetes.io/name": "netbird-router",
			},
		}
		updatedDeployment.Spec.Template.Spec.Tolerations = nbrp.Spec.Tolerations
		updatedDeployment.Spec.Template.Spec.NodeSelector = nbrp.Spec.NodeSelector
		updatedDeployment.Spec.Template.ObjectMeta.Labels = podLabels
		updatedDeployment.Spec.Template.Spec.Volumes = nbrp.Spec.Volumes
		if len(updatedDeployment.Spec.Template.Spec.Containers) != 1 {
			updatedDeployment.Spec.Template.Spec.Containers = []corev1.Container{{}}
		}
		updatedDeployment.Spec.Template.Spec.Containers[0].Name = "netbird"
		updatedDeployment.Spec.Template.Spec.Containers[0].Image = r.ClientImage
		updatedDeployment.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
			{
				Name: "NB_SETUP_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: nbrp.Name,
						},
						Key: "setupKey",
					},
				},
			},
			{
				Name:  "NB_MANAGEMENT_URL",
				Value: r.ManagementURL,
			},
		}
		updatedDeployment.Spec.Template.Spec.Containers[0].SecurityContext = r.buildSecurityContext(nbrp)
		updatedDeployment.Spec.Template.Spec.Containers[0].Resources = nbrp.Spec.Resources
		updatedDeployment.Spec.Template.Spec.Containers[0].VolumeMounts = nbrp.Spec.VolumeMounts
		updatedDeployment.Spec.Template.Spec.Containers[0].StartupProbe = routingPeerStartupProbe()
		updatedDeployment.Spec.Template.Spec.Containers[0].ReadinessProbe = routingPeerReadinessProbe()
		updatedDeployment.Spec.Template.Spec.Containers[0].LivenessProbe = routingPeerLivenessProbe()

		patch := client.StrategicMergeFrom(&routingPeerDeployment)
		bs, _ := patch.Data(updatedDeployment)
		// To ensure no useless patching is done to the deployment being watched
		// Minimum patch size is 2 for "{}"
		if len(bs) <= 2 {
			return nil
		}
		err = r.Client.Patch(ctx, updatedDeployment, patch)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating Deployment", "err", err)
			nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error updating Deployment: %v", err))
			return err
		}
	}

	return err
}

// handleRouter reconcile network routing peer in NetBird management API
func (r *NBRoutingPeerReconciler) handleRouter(ctx context.Context, nbrp *nbv1.NBRoutingPeer, nbGroup nbv1.NBGroup, logger logr.Logger) error {
	// Check NetworkRouter exists
	routers, err := r.Netbird.Networks.Routers(*nbrp.Status.NetworkID).List(ctx)

	if err != nil {
		logger.Error(errNetBirdAPI, "error listing network routers", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error listing network routers: %v", err))
		return err
	}

	if nbrp.Status.RouterID == nil || len(routers) == 0 {
		if len(routers) > 0 {
			// Router exists but isn't saved to status
			nbrp.Status.RouterID = &routers[0].Id
		} else {
			// Create network router
			router, err := r.Netbird.Networks.Routers(*nbrp.Status.NetworkID).Create(ctx, api.NetworkRouterRequest{
				Enabled:    true,
				Masquerade: true,
				Metric:     9999,
				PeerGroups: &[]string{*nbGroup.Status.GroupID},
			})

			if err != nil {
				logger.Error(errNetBirdAPI, "error creating network router", "err", err)
				nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error creating network router: %v", err))
				return err
			}

			nbrp.Status.RouterID = &router.Id
		}
	} else {
		// Ensure network router settings are correct
		if !routers[0].Enabled || !routers[0].Masquerade || routers[0].Metric != 9999 || len(*routers[0].PeerGroups) != 1 || (*routers[0].PeerGroups)[0] != *nbGroup.Status.GroupID {
			_, err = r.Netbird.Networks.Routers(*nbrp.Status.NetworkID).Update(ctx, routers[0].Id, api.NetworkRouterRequest{
				Enabled:    true,
				Masquerade: true,
				Metric:     9999,
				PeerGroups: &[]string{*nbGroup.Status.GroupID},
			})

			if err != nil {
				logger.Error(errNetBirdAPI, "error updating network router", "err", err)
				nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error updating network router: %v", err))
				return err
			}
		}
	}

	return nil
}

const setupKeyIDAnnotation = "netbird.io/setup-key-id"

// handleSetupKey reconcile setup key and regenerate if invalid
func (r *NBRoutingPeerReconciler) handleSetupKey(ctx context.Context, req ctrl.Request, nbrp *nbv1.NBRoutingPeer, nbGroup nbv1.NBGroup, logger logr.Logger) (*ctrl.Result, error) {
	networkName := r.ClusterName
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
	}

	if nbrp.Status.SetupKeyID == nil {
		if err := r.createOrAdoptSetupKey(ctx, req, nbrp, nbGroup, networkName, logger); err != nil {
			return &ctrl.Result{}, err
		}
		return nil, nil
	}

	// Check SetupKey is not revoked
	setupKey, err := r.Netbird.SetupKeys.Get(ctx, *nbrp.Status.SetupKeyID)
	if err != nil && !isSetupKeyNotFound(err) {
		logger.Error(errNetBirdAPI, "error getting setup key", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error getting setup key: %v", err))
		return &ctrl.Result{}, err
	}

	if isSetupKeyNotFound(err) || setupKey == nil || setupKey.Revoked {
		if setupKey != nil && setupKey.Revoked {
			if err = r.deleteSetupKey(ctx, *nbrp.Status.SetupKeyID); err != nil {
				logger.Error(errNetBirdAPI, "error deleting setup key", "err", err)
				nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error deleting setup key: %v", err))
				return &ctrl.Result{}, err
			}
		}

		nbrp.Status.SetupKeyID = nil
		// Requeue to avoid repeating code
		return &ctrl.Result{Requeue: true}, nil
	}

	// Check if secret is valid
	skSecret := corev1.Secret{}
	err = r.Client.Get(ctx, req.NamespacedName, &skSecret)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting Secret", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error getting secret: %v", err))
		return &ctrl.Result{}, err
	}

	hasKey := err == nil && len(skSecret.Data["setupKey"]) > 0
	secretKeyID := skSecret.Annotations[setupKeyIDAnnotation]
	secretMismatch := secretKeyID != "" && secretKeyID != *nbrp.Status.SetupKeyID
	if errors.IsNotFound(err) || !hasKey || secretMismatch {
		if err = r.deleteSetupKey(ctx, *nbrp.Status.SetupKeyID); err != nil {
			logger.Error(errNetBirdAPI, "error deleting setup key", "err", err)
			nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error deleting setup key: %v", err))
			return &ctrl.Result{}, err
		}

		nbrp.Status.SetupKeyID = nil
		if errors.IsNotFound(err) || !hasKey {
			nbrp.Status.Conditions = nbv1.NBConditionFalse("Gone", "generated secret was deleted")
		}
		// Requeue to avoid repeating code
		return &ctrl.Result{Requeue: true}, nil
	}

	return nil, nil
}

func (r *NBRoutingPeerReconciler) createOrAdoptSetupKey(ctx context.Context, req ctrl.Request, nbrp *nbv1.NBRoutingPeer, nbGroup nbv1.NBGroup, networkName string, logger logr.Logger) error {
	adopted, err := r.adoptOrCleanupSecretKey(ctx, req, nbrp, logger)
	if err != nil || adopted {
		return err
	}

	setupKey, err := r.Netbird.SetupKeys.Create(ctx, api.CreateSetupKeyRequest{
		AutoGroups: []string{*nbGroup.Status.GroupID},
		Ephemeral:  new(true),
		Name:       networkName,
		Type:       "reusable",
	})
	if err != nil {
		logger.Error(errNetBirdAPI, "error creating setup key", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error creating setup key: %v", err))
		return err
	}

	if err = r.upsertSetupKeySecret(ctx, req, nbrp, *setupKey); err != nil {
		if delErr := r.deleteSetupKey(ctx, setupKey.Id); delErr != nil {
			logger.Error(errNetBirdAPI, "error deleting setup key", "err", delErr)
		}
		logger.Error(errKubernetesAPI, "error creating Secret", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error creating secret: %v", err))
		return err
	}

	nbrp.Status.SetupKeyID = &setupKey.Id
	if err = r.Client.Status().Update(ctx, nbrp); err != nil {
		nbrp.Status.SetupKeyID = nil
		logger.Error(errKubernetesAPI, "error updating NBRoutingPeer Status", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error updating NBRoutingPeer Status: %v", err))
		return err
	}

	return nil
}

func (r *NBRoutingPeerReconciler) adoptOrCleanupSecretKey(ctx context.Context, req ctrl.Request, nbrp *nbv1.NBRoutingPeer, logger logr.Logger) (bool, error) {
	var existingSecret corev1.Secret
	err := r.Client.Get(ctx, req.NamespacedName, &existingSecret)
	if errors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		logger.Error(errKubernetesAPI, "error getting Secret", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error getting secret: %v", err))
		return false, err
	}

	secretKeyID := existingSecret.Annotations[setupKeyIDAnnotation]
	if secretKeyID == "" {
		return false, nil
	}
	if !hasSecretOwner(&existingSecret, nbrp) {
		conflictErr := fmt.Errorf("secret %s/%s has %s annotation without matching NBRoutingPeer owner reference", existingSecret.Namespace, existingSecret.Name, setupKeyIDAnnotation)
		logger.Error(errKubernetesAPI, "refusing to use unowned setup key secret", "err", conflictErr)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", conflictErr.Error())
		return false, conflictErr
	}

	existingKey, err := r.Netbird.SetupKeys.Get(ctx, secretKeyID)
	if isSetupKeyNotFound(err) {
		return false, nil
	}
	if err != nil {
		logger.Error(errNetBirdAPI, "error getting setup key", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error getting setup key: %v", err))
		return false, err
	}
	if existingKey == nil {
		return false, nil
	}

	if existingKey.Revoked || !existingKey.Valid || len(existingSecret.Data["setupKey"]) == 0 {
		if err = r.deleteSetupKey(ctx, secretKeyID); err != nil {
			logger.Error(errNetBirdAPI, "error deleting setup key", "err", err)
			nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error deleting setup key: %v", err))
			return false, err
		}
		return false, nil
	}

	nbrp.Status.SetupKeyID = &secretKeyID
	if err = r.Client.Status().Update(ctx, nbrp); err != nil {
		nbrp.Status.SetupKeyID = nil
		logger.Error(errKubernetesAPI, "error updating NBRoutingPeer Status", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error updating NBRoutingPeer Status: %v", err))
		return false, err
	}

	return true, nil
}

func (r *NBRoutingPeerReconciler) upsertSetupKeySecret(ctx context.Context, req ctrl.Request, nbrp *nbv1.NBRoutingPeer, setupKey api.SetupKeyClear) error {
	ownerRef := metav1.OwnerReference{
		APIVersion:         nbv1.GroupVersion.Identifier(),
		Kind:               "NBRoutingPeer",
		Name:               nbrp.Name,
		UID:                nbrp.UID,
		Controller:         new(true),
		BlockOwnerDeletion: new(true),
	}
	skSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            nbrp.Name,
			Namespace:       nbrp.Namespace,
			OwnerReferences: []metav1.OwnerReference{ownerRef},
			Labels:          r.DefaultLabels,
			Annotations: map[string]string{
				setupKeyIDAnnotation: setupKey.Id,
			},
		},
		StringData: map[string]string{
			"setupKey": setupKey.Key,
		},
	}
	err := r.Client.Create(ctx, &skSecret)
	if !errors.IsAlreadyExists(err) {
		return err
	}

	var existing corev1.Secret
	if err := r.Client.Get(ctx, req.NamespacedName, &existing); err != nil {
		return err
	}
	if len(existing.OwnerReferences) > 0 && !hasSecretOwner(&existing, nbrp) {
		return fmt.Errorf("secret %s/%s is owned by another resource", existing.Namespace, existing.Name)
	}
	if !hasSecretOwner(&existing, nbrp) {
		existing.OwnerReferences = append(existing.OwnerReferences, ownerRef)
	}
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations[setupKeyIDAnnotation] = setupKey.Id
	if existing.Data == nil {
		existing.Data = map[string][]byte{}
	}
	existing.Data["setupKey"] = []byte(setupKey.Key)
	return r.Client.Update(ctx, &existing)
}

func hasSecretOwner(secret *corev1.Secret, nbrp *nbv1.NBRoutingPeer) bool {
	return slices.ContainsFunc(secret.OwnerReferences, func(ref metav1.OwnerReference) bool {
		return ref.UID == nbrp.UID
	})
}

func (r *NBRoutingPeerReconciler) deleteSetupKey(ctx context.Context, id string) error {
	err := r.Netbird.SetupKeys.Delete(ctx, id)
	if err != nil && !isSetupKeyNotFound(err) {
		return err
	}
	return nil
}

func isSetupKeyNotFound(err error) bool {
	return netbird.IsNotFound(err)
}

// handleGroup creates/updates NBGroup for routing peer
func (r *NBRoutingPeerReconciler) handleGroup(ctx context.Context, req ctrl.Request, nbrp *nbv1.NBRoutingPeer, logger logr.Logger) (*nbv1.NBGroup, *ctrl.Result, error) {
	networkName := r.ClusterName
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
	}

	// Check if NetBird Group exists
	nbGroup := nbv1.NBGroup{}
	err := r.Client.Get(ctx, req.NamespacedName, &nbGroup)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting NBGroup", "err", err)
		nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error getting NBGroup: %v", err))
		return nil, &ctrl.Result{}, err
	}

	if errors.IsNotFound(err) {
		nbGroup = nbv1.NBGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nbrp.Name,
				Namespace: nbrp.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         nbv1.GroupVersion.Identifier(),
						Kind:               "NBRoutingPeer",
						Name:               nbrp.Name,
						UID:                nbrp.UID,
						BlockOwnerDeletion: new(true),
					},
				},
				Finalizers: []string{"netbird.io/group-cleanup", "netbird.io/routing-peer-cleanup"},
				Labels:     r.DefaultLabels,
			},
			Spec: nbv1.NBGroupSpec{
				Name: networkName,
			},
		}

		err = r.Client.Create(ctx, &nbGroup)

		if err != nil {
			logger.Error(errKubernetesAPI, "error creating NBGroup", "err", err)
			nbrp.Status.Conditions = nbv1.NBConditionFalse("internalError", fmt.Sprintf("error creating NBGroup: %v", err))
			return nil, &ctrl.Result{}, err
		}

		// Requeue after 5 seconds to ensure group creation is successful by NBGroup controller.
		return nil, &ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if nbGroup.Status.GroupID == nil {
		// Group is not yet created successfully, requeue
		return nil, &ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	return &nbGroup, nil, nil
}

// handleNetwork Create/Update NetBird Network
func (r *NBRoutingPeerReconciler) handleNetwork(ctx context.Context, req ctrl.Request, nbrp *nbv1.NBRoutingPeer, logger logr.Logger) error {
	networkName := r.ClusterName
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
	}

	if nbrp.Status.NetworkID == nil {
		// Check if network exists
		networks, err := r.Netbird.Networks.List(ctx)
		if err != nil {
			logger.Error(errNetBirdAPI, "error listing networks", "err", err)
			nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error listing networks: %v", err))
			return err
		}
		var network *api.Network
		for _, n := range networks {
			if n.Name == networkName {
				logger.Info("network already exists", "network-id", n.Id)
				network = &n
			}
		}

		if network != nil {
			nbrp.Status.NetworkID = &network.Id
		} else {
			logger.Info("creating network", "name", networkName)
			network, err := r.Netbird.Networks.Create(ctx, api.NetworkRequest{
				Name:        networkName,
				Description: &networkDescription,
			})
			if err != nil {
				logger.Error(errNetBirdAPI, "error creating network", "err", err)
				nbrp.Status.Conditions = nbv1.NBConditionFalse("APIError", fmt.Sprintf("error creating network: %v", err))
				return err
			}

			nbrp.Status.NetworkID = &network.Id
		}
	}
	return nil
}

func (r *NBRoutingPeerReconciler) handleDelete(ctx context.Context, req ctrl.Request, nbrp *nbv1.NBRoutingPeer, logger logr.Logger) (ctrl.Result, error) {
	nbDeployment := appsv1.Deployment{}
	err := r.Client.Get(ctx, req.NamespacedName, &nbDeployment)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting Deployment", "err", err)
		return ctrl.Result{}, err
	}
	if err == nil {
		err = r.Client.Delete(ctx, &nbDeployment)
		if err != nil {
			logger.Error(errKubernetesAPI, "error deleting Deployment", "err", err)
			return ctrl.Result{}, err
		}
	}

	setupKeyID := ""
	if nbrp.Status.SetupKeyID != nil {
		setupKeyID = *nbrp.Status.SetupKeyID
	} else {
		var skSecret corev1.Secret
		secErr := r.Client.Get(ctx, req.NamespacedName, &skSecret)
		if secErr != nil && !errors.IsNotFound(secErr) {
			logger.Error(errKubernetesAPI, "error getting Secret", "err", secErr)
			return ctrl.Result{}, secErr
		}
		if secErr == nil && hasSecretOwner(&skSecret, nbrp) {
			setupKeyID = skSecret.Annotations[setupKeyIDAnnotation]
		}
	}

	if setupKeyID != "" {
		logger.Info("Deleting setup key", "id", setupKeyID)
		err = r.deleteSetupKey(ctx, setupKeyID)
		if err != nil {
			logger.Error(errNetBirdAPI, "error deleting setupKey", "err", err)
			return ctrl.Result{}, err
		}

		nbrp.Status.SetupKeyID = nil
		logger.Info("Setup key deleted", "id", setupKeyID)
	}

	nbGroup := nbv1.NBGroup{}
	err = r.Client.Get(ctx, req.NamespacedName, &nbGroup)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting NBGroup", "err", err)
		return ctrl.Result{}, err
	}

	if nbrp.Status.NetworkID != nil {
		nbResourceList := nbv1.NBResourceList{}
		err = r.Client.List(ctx, &nbResourceList)
		if err != nil {
			logger.Error(errKubernetesAPI, "error listing NBResource", "err", err)
			return ctrl.Result{}, err
		}

		for _, nbrs := range nbResourceList.Items {
			if nbrs.Spec.NetworkID == *nbrp.Status.NetworkID {
				logger.Info("Deleting NBResource", "namespace", nbrs.Namespace, "name", nbrs.Name)
				err = r.Client.Delete(ctx, &nbrs)
				if err != nil {
					logger.Error(errKubernetesAPI, "error deleting NBResource", "err", err)
					return ctrl.Result{}, err
				}
			}
		}

		if len(nbResourceList.Items) == 0 {
			logger.Info("Deleting NetBird Network", "id", *nbrp.Status.NetworkID)
			err = r.Netbird.Networks.Delete(ctx, *nbrp.Status.NetworkID)
			if err != nil && !strings.Contains(err.Error(), "not found") {
				logger.Error(errNetBirdAPI, "error deleting Network", "err", err)
				return ctrl.Result{}, err
			}

			nbrp.Status.NetworkID = nil
			nbrp.Status.RouterID = nil
		}
	}

	if nbGroup.Spec.Name != "" && slices.Contains(nbGroup.Finalizers, "netbird.io/routing-peer-cleanup") {
		nbGroup.Finalizers = util.Without(nbGroup.Finalizers, "netbird.io/routing-peer-cleanup")
		logger.Info("Removing netbird.io/routing-peer-cleanup finalizer NBGroup", "namespace", nbGroup.Namespace, "name", nbGroup.Name)
		err = r.Client.Update(ctx, &nbGroup)
		if err != nil {
			logger.Error(errKubernetesAPI, "error deleting NBGroup", "err", err)
			return ctrl.Result{}, err
		}
	}

	if nbrp.Status.NetworkID != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if len(nbrp.Finalizers) > 0 {
		logger.Info("Removing finalizers", "namespace", nbrp.Namespace, "name", nbrp.Name)
		nbrp.Finalizers = nil
		err = r.Client.Update(ctx, nbrp)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating NBRoutingPeer finalizers", "err", err)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// buildSecurityContext creates the appropriate SecurityContext based on the NBRoutingPeer spec
func (r *NBRoutingPeerReconciler) buildSecurityContext(nbrp *nbv1.NBRoutingPeer) *corev1.SecurityContext {
	securityContext := &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{
				"NET_ADMIN",
			},
		},
	}

	// Set privileged mode if specified
	if nbrp.Spec.Privileged != nil && *nbrp.Spec.Privileged {
		securityContext.Privileged = nbrp.Spec.Privileged
	}

	return securityContext
}

// routingPeerProbe builds an exec probe running "netbird status --check <check>".
// Every field the API server would default is set explicitly, so the update path's
// strategic merge patch stays empty when nothing changed.
func routingPeerProbe(check string, periodSeconds, failureThreshold int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{"netbird", "status", "--check", check},
			},
		},
		TimeoutSeconds:   5,
		PeriodSeconds:    periodSeconds,
		SuccessThreshold: 1,
		FailureThreshold: failureThreshold,
	}
}

// routingPeerStartupProbe holds off the readiness and liveness probes until the
// peer has connected to management and signal for the first time (up to 5 minutes).
func routingPeerStartupProbe() *corev1.Probe {
	return routingPeerProbe("startup", 10, 30)
}

// routingPeerReadinessProbe marks the pod not ready while the daemon is logged out.
func routingPeerReadinessProbe() *corev1.Probe {
	return routingPeerProbe("ready", 10, 3)
}

// routingPeerLivenessProbe restarts the container when the daemon stays logged out
// (NeedsLogin, LoginFailed or SessionExpired) for about a minute, for example after
// management deleted the ephemeral peer. The daemon never logs in again on its own;
// a restart runs "netbird up" with the setup key and enrolls the peer again.
func routingPeerLivenessProbe() *corev1.Probe {
	return routingPeerProbe("ready", 10, 6)
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBRoutingPeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1.NBRoutingPeer{}).
		Named("nbroutingpeer").
		Watches(&appsv1.Deployment{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &nbv1.NBRoutingPeer{})).
		Watches(&corev1.Secret{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &nbv1.NBRoutingPeer{})).
		Watches(&nbv1.NBGroup{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &nbv1.NBRoutingPeer{})).
		Complete(r)
}
