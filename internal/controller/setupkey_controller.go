package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/ssautil"
	nbv1alpha1ac "github.com/netbirdio/kubernetes-operator/pkg/applyconfigurations/api/v1alpha1"
)

const (
	SetupKeyFinalizer = "netbird.io/setupkey"
	SetupKeySecretKey = "setup-key"
)

type SetupKeyReconciler struct {
	client.Client

	Netbird *netbird.Client
}

// +kubebuilder:rbac:groups=netbird.io,resources=setupkeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=setupkeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=setupkeys/finalizers,verbs=update
func (r *SetupKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	setupKey := nbv1alpha1.SetupKey{}
	err := r.Get(ctx, req.NamespacedName, &setupKey)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !setupKey.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, setupKey)
	}

	// Get ids for auto groups.
	autoGroupIDs := []string{}
	for _, ref := range setupKey.Spec.AutoGroups {
		switch {
		case ref.ID != nil:
			_, err := r.Netbird.Groups.Get(ctx, *ref.ID)
			if err != nil {
				return ctrl.Result{}, err
			}
			autoGroupIDs = append(autoGroupIDs, *ref.ID)
		case ref.LocalRef != nil:
			group := nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.LocalRef.Name,
					Namespace: setupKey.Namespace,
				},
			}
			err = r.Client.Get(ctx, client.ObjectKeyFromObject(&group), &group)
			if err != nil {
				return ctrl.Result{}, err
			}
			if group.Status.GroupID == nil {
				return ctrl.Result{}, fmt.Errorf("group %s in auto groups list is not ready", group.Name)
			}
			autoGroupIDs = append(autoGroupIDs, *group.Status.GroupID)
		}
	}

	// Set finalizer on the setup key.
	setupKeyAC := nbv1alpha1ac.SetupKey(req.Name, req.Namespace).WithFinalizers(SetupKeyFinalizer)
	err = r.Client.Apply(ctx, setupKeyAC)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Check if setup key is up to date.
	ok, err := func() (bool, error) {
		if setupKey.Status.SetupKeyID == nil {
			return false, nil
		}

		// Check setup key in Netbird.
		resp, err := r.Netbird.SetupKeys.Get(ctx, *setupKey.Status.SetupKeyID)
		if netbird.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		switch resp.State {
		case "valid":
		case "overused":
			return false, errors.New("setup key is overused")
		default:
			return false, nil
		}

		// Secret exists and has not been modified.
		secret := &corev1.Secret{}
		err = r.Client.Get(ctx, client.ObjectKey{Name: setupKey.SecretName(), Namespace: req.Namespace}, secret)
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if resp.Key[:5] != string(secret.Data[SetupKeySecretKey])[:5] {
			return false, nil
		}

		// Auto groups have not been changed.
		setupKeyReq := api.PutApiSetupKeysKeyIdJSONRequestBody{
			AutoGroups: autoGroupIDs,
		}
		_, err = r.Netbird.SetupKeys.Update(ctx, *setupKey.Status.SetupKeyID, setupKeyReq)
		if err != nil {
			return false, err
		}

		return true, nil
	}()
	if err != nil {
		return ctrl.Result{}, err
	}
	if ok {
		return ctrl.Result{RequeueAfter: 15 * time.Minute}, nil
	}
	oldSetupKeyID := setupKey.Status.SetupKeyID

	// Setup key does not exist so we create one.
	expiresIn := 0
	if setupKey.Spec.Duration != nil {
		expiresIn = int(setupKey.Spec.Duration.Seconds())
	}
	setupKeyReq := api.PostApiSetupKeysJSONRequestBody{
		AllowExtraDnsLabels: ptr.To(false),
		AutoGroups:          autoGroupIDs,
		Ephemeral:           ptr.To(setupKey.Spec.Ephemeral),
		ExpiresIn:           expiresIn,
		Name:                req.Name,
		Type:                "reusable",
		UsageLimit:          0,
	}
	resp, err := r.Netbird.SetupKeys.Create(ctx, setupKeyReq)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Update the status with the id.
	setupKeyAC = nbv1alpha1ac.SetupKey(req.Name, req.Namespace).WithStatus(nbv1alpha1ac.SetupKeyStatus().WithSetupKeyID(resp.Id))
	err = r.Client.Status().Apply(ctx, setupKeyAC)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Create the secret containing the key.
	owner, err := ssautil.OwnerReference(&setupKey, r.Scheme())
	if err != nil {
		return ctrl.Result{}, err
	}
	data := map[string]string{
		SetupKeySecretKey: resp.Key,
	}
	secret := corev1ac.Secret(setupKey.SecretName(), req.Namespace).
		WithStringData(data).
		WithOwnerReferences(owner)
	err = r.Client.Apply(ctx, secret)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Delete the old status key if we are recreating.
	if oldSetupKeyID != nil {
		err = r.Netbird.SetupKeys.Delete(ctx, *oldSetupKeyID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{RequeueAfter: 15 * time.Minute}, nil
}

func (r *SetupKeyReconciler) reconcileDelete(ctx context.Context, setupKey nbv1alpha1.SetupKey) (ctrl.Result, error) {
	if setupKey.Status.SetupKeyID != nil {
		err := r.Netbird.SetupKeys.Delete(ctx, *setupKey.Status.SetupKeyID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	setupKeyAC := nbv1alpha1ac.SetupKey(setupKey.Name, setupKey.Namespace).WithFinalizers()
	err := r.Client.Apply(ctx, setupKeyAC)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *SetupKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.SetupKey{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
