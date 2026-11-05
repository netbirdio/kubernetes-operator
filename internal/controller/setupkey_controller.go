// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdutil"
)

const (
	SetupKeySecretKey = "setup-key"

	// setupKeyResyncInterval is how often a setup key is checked against NetBird
	// when nothing is due sooner.
	setupKeyResyncInterval = 15 * time.Minute

	// setupKeyRetryInterval is how long to wait when a key is past its expiry by
	// the operator's clock but NetBird does not report it expired yet, as happens
	// while the two clocks disagree.
	setupKeyRetryInterval = 10 * time.Second

	// setupKeyPrefixLen is how many characters of an existing key NetBird
	// returns; the rest is masked.
	setupKeyPrefixLen = 5
)

type SetupKeyReconciler struct {
	client.Client

	Netbird *netbird.Client
	// Clock is what setup key renewal and expiry go by. It defaults to the real
	// clock.
	Clock clock.PassiveClock
}

// setupKeyState is what checkSetupKey found out about the setup key in the
// status.
type setupKeyState int

const (
	// setupKeyUsable is a key that NetBird reports valid and that the Secret
	// holds.
	setupKeyUsable setupKeyState = iota
	// setupKeyDetached is a key that NetBird reports valid but that the Secret
	// no longer holds, because the Secret is gone or was changed. Whatever
	// copied the Secret before may still hold the key.
	setupKeyDetached
	// setupKeyDead is a key that nothing can enroll with any more: none is
	// recorded, NetBird does not have it, or NetBird reports it expired or
	// revoked.
	setupKeyDead
)

// setupKeyCheck is the outcome of checkSetupKey.
type setupKeyCheck struct {
	state setupKeyState
	// reason says why the key is not usable.
	reason string
	// expires is when the key expires, and zero for a key that does not.
	expires time.Time
}

// +kubebuilder:rbac:groups=netbird.io,resources=setupkeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=setupkeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=setupkeys/finalizers,verbs=update
func (r *SetupKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	setupKey := &nbv1alpha1.SetupKey{}
	err := r.Get(ctx, req.NamespacedName, setupKey)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	owner, err := k8sutil.ControllerReference(setupKey, r.Client.Scheme())
	if err != nil {
		return ctrl.Result{}, err
	}
	sp := patch.NewSerialPatcher(setupKey, r.Client)

	if !setupKey.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sp, setupKey)
	}

	controllerutil.AddFinalizer(setupKey, k8sutil.Finalizer("setupkey"))
	err = sp.Patch(ctx, setupKey)
	if err != nil {
		return ctrl.Result{}, err
	}

	autoGroupIDs, err := netbirdutil.GetGroupIDs(ctx, r.Client, r.Netbird, setupKey.Spec.AutoGroups, setupKey.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	check, err := r.checkSetupKey(ctx, setupKey, autoGroupIDs)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.reconcilePreviousSetupKeys(ctx, setupKey, autoGroupIDs)
	if err != nil {
		return ctrl.Result{}, err
	}

	now := r.now()
	expires := check.expires
	_, renews := renewAt(setupKey, expires)
	log := ctrl.LoggerFrom(ctx)
	switch {
	case check.state == setupKeyDead, check.state == setupKeyDetached && !renews:
		// Nothing can enroll with a dead key. A detached key is not kept either
		// unless the SetupKey renews, as deleting the Secret is how a key is
		// rotated by hand. Both are deleted and replaced at once, in that order:
		// once the status records the new key nothing remembers the old one, so
		// a failure in between would leave it behind for good.
		oldSetupKeyID := setupKey.Status.SetupKeyID
		if oldSetupKeyID != "" {
			err = r.Netbird.SetupKeys.Delete(ctx, oldSetupKeyID)
			if err != nil && !netbird.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
		expires, err = r.createSetupKey(ctx, sp, setupKey, owner, autoGroupIDs)
		if err != nil {
			return ctrl.Result{}, err
		}
		if oldSetupKeyID == "" {
			log.Info("Created setup key", "setupKeyID", setupKey.Status.SetupKeyID)
			break
		}
		log.Info("Replaced setup key", "reason", check.reason, "setupKeyID", setupKey.Status.SetupKeyID,
			"deletedSetupKeyID", oldSetupKeyID)
	case check.state == setupKeyDetached, renewalDue(setupKey, expires, now):
		// The key is still valid and whatever copied the Secret may still hold
		// it, so it is kept until it expires.
		reason := "due for renewal"
		if check.state == setupKeyDetached {
			reason = check.reason
		}
		previous := nbv1alpha1.PreviousSetupKey{
			SetupKeyID: setupKey.Status.SetupKeyID,
			ExpiresAt:  metav1.NewTime(expires),
		}
		setupKey.Status.PreviousSetupKeys = append(setupKey.Status.PreviousSetupKeys, previous)
		expires, err = r.createSetupKey(ctx, sp, setupKey, owner, autoGroupIDs)
		if err != nil {
			return ctrl.Result{}, err
		}
		log.Info("Renewed setup key", "reason", reason, "setupKeyID", setupKey.Status.SetupKeyID,
			"previousSetupKeyID", previous.SetupKeyID, "previousExpiresAt", previous.ExpiresAt)
	}

	setupKey.Status.ExpiresAt = nil
	if !expires.IsZero() {
		setupKey.Status.ExpiresAt = new(metav1.NewTime(expires))
	}
	conditions.MarkTrue(setupKey, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	err = sp.Patch(ctx, setupKey, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueAfter(setupKey, expires, now)}, nil
}

// checkSetupKey reports the state of the setup key in the status and when it
// expires. A key that NetBird reports valid gets its auto groups updated.
func (r *SetupKeyReconciler) checkSetupKey(ctx context.Context, setupKey *nbv1alpha1.SetupKey, autoGroupIDs []string) (setupKeyCheck, error) {
	if setupKey.Status.SetupKeyID == "" {
		return setupKeyCheck{state: setupKeyDead, reason: "no setup key recorded"}, nil
	}

	// Check setup key in Netbird.
	resp, err := r.Netbird.SetupKeys.Get(ctx, setupKey.Status.SetupKeyID)
	if netbird.IsNotFound(err) {
		return setupKeyCheck{state: setupKeyDead, reason: "setup key not found"}, nil
	}
	if err != nil {
		return setupKeyCheck{}, err
	}

	switch resp.State {
	case "valid":
	case "overused":
		return setupKeyCheck{}, errors.New("setup key is overused")
	default:
		return setupKeyCheck{state: setupKeyDead, reason: "setup key is " + resp.State}, nil
	}
	check := setupKeyCheck{state: setupKeyUsable, expires: resp.Expires}

	// Auto groups have not been changed.
	setupKeyReq := api.PutApiSetupKeysKeyIdJSONRequestBody{
		AutoGroups: autoGroupIDs,
	}
	_, err = r.Netbird.SetupKeys.Update(ctx, setupKey.Status.SetupKeyID, setupKeyReq)
	if err != nil {
		return setupKeyCheck{}, err
	}

	// Secret exists and has not been modified.
	secret := &corev1.Secret{}
	err = r.Client.Get(ctx, client.ObjectKey{Name: setupKey.SecretName(), Namespace: setupKey.Namespace}, secret)
	if kerrors.IsNotFound(err) {
		check.state = setupKeyDetached
		check.reason = "Secret not found"
		return check, nil
	}
	if err != nil {
		return setupKeyCheck{}, err
	}
	if keyPrefix(resp.Key) != keyPrefix(string(secret.Data[SetupKeySecretKey])) {
		check.state = setupKeyDetached
		check.reason = "Secret does not hold the setup key"
	}
	return check, nil
}

// keyPrefix returns the part of a setup key that NetBird returns unmasked.
func keyPrefix(key string) string {
	return key[:min(len(key), setupKeyPrefixLen)]
}

// createSetupKey creates a setup key, records it in the status and stores it in
// the Secret. It returns when the key expires.
func (r *SetupKeyReconciler) createSetupKey(ctx context.Context, sp *patch.SerialPatcher, setupKey *nbv1alpha1.SetupKey, owner *metav1ac.OwnerReferenceApplyConfiguration, autoGroupIDs []string) (time.Time, error) {
	expiresIn := 0
	if setupKey.Spec.Duration != nil {
		expiresIn = int(setupKey.Spec.Duration.Seconds())
	}
	setupKeyReq := api.PostApiSetupKeysJSONRequestBody{
		AllowExtraDnsLabels: &setupKey.Spec.AllowExtraDnsLabels,
		AutoGroups:          autoGroupIDs,
		Ephemeral:           new(setupKey.Spec.Ephemeral),
		ExpiresIn:           expiresIn,
		Name:                setupKey.Spec.Name,
		Type:                "reusable",
		UsageLimit:          0,
	}
	resp, err := r.Netbird.SetupKeys.Create(ctx, setupKeyReq)
	if err != nil {
		return time.Time{}, err
	}
	setupKey.Status.SetupKeyID = resp.Id
	err = sp.Patch(ctx, setupKey)
	if err != nil {
		// Nothing records the key yet, so nothing would ever delete it.
		deleteErr := r.Netbird.SetupKeys.Delete(ctx, resp.Id)
		if deleteErr != nil && !netbird.IsNotFound(deleteErr) {
			ctrl.LoggerFrom(ctx).Error(deleteErr, "Failed to delete the setup key the status could not record", "setupKeyID", resp.Id)
		}
		return time.Time{}, err
	}

	// Create the secret containing the key.
	data := map[string]string{
		SetupKeySecretKey: resp.Key,
	}
	secret := corev1ac.Secret(setupKey.SecretName(), setupKey.Namespace).
		WithStringData(data).
		WithOwnerReferences(owner)
	err = r.Client.Apply(ctx, secret, client.ForceOwnership)
	if err != nil {
		r.deleteUndeliveredSetupKey(ctx, setupKey, resp)
		return time.Time{}, err
	}
	return resp.Expires, nil
}

// deleteUndeliveredSetupKey deletes a setup key after a failed write of the
// Secret, unless the Secret turns out to hold it, as a failed write may still
// have gone through. The status records the key, so the next reconcile finds it
// gone and creates another. Left alone, a SetupKey that renews would instead
// keep it as a replaced key, although nothing can have copied it, and pile up
// one more for each failed write.
func (r *SetupKeyReconciler) deleteUndeliveredSetupKey(ctx context.Context, setupKey *nbv1alpha1.SetupKey, created *api.SetupKeyClear) {
	log := ctrl.LoggerFrom(ctx).WithValues("setupKeyID", created.Id)
	secret := &corev1.Secret{}
	err := r.Client.Get(ctx, client.ObjectKey{Name: setupKey.SecretName(), Namespace: setupKey.Namespace}, secret)
	switch {
	case kerrors.IsNotFound(err):
	case err != nil:
		log.Error(err, "Failed to check whether the Secret holds the setup key, keeping it")
		return
	case keyPrefix(created.Key) == keyPrefix(string(secret.Data[SetupKeySecretKey])):
		return
	}
	err = r.Netbird.SetupKeys.Delete(ctx, created.Id)
	if err != nil && !netbird.IsNotFound(err) {
		log.Error(err, "Failed to delete the setup key the Secret does not hold")
		return
	}
	log.Info("Deleted setup key the Secret could not store")
}

// reconcilePreviousSetupKeys keeps the auto groups of the setup keys replaced by
// a renewal up to date while NetBird reports them valid, and deletes them once
// it does not, because they expired or someone revoked them. The operator's
// clock only schedules the check: NetBird decides when a key has expired.
func (r *SetupKeyReconciler) reconcilePreviousSetupKeys(ctx context.Context, setupKey *nbv1alpha1.SetupKey, autoGroupIDs []string) error {
	var kept []nbv1alpha1.PreviousSetupKey
	for _, previous := range setupKey.Status.PreviousSetupKeys {
		resp, err := r.Netbird.SetupKeys.Get(ctx, previous.SetupKeyID)
		if netbird.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if resp.State != "valid" {
			err = r.Netbird.SetupKeys.Delete(ctx, previous.SetupKeyID)
			if err != nil && !netbird.IsNotFound(err) {
				return err
			}
			ctrl.LoggerFrom(ctx).Info("Deleted replaced setup key", "setupKeyID", previous.SetupKeyID, "state", resp.State)
			continue
		}
		setupKeyReq := api.PutApiSetupKeysKeyIdJSONRequestBody{
			AutoGroups: autoGroupIDs,
		}
		_, err = r.Netbird.SetupKeys.Update(ctx, previous.SetupKeyID, setupKeyReq)
		if err != nil {
			return err
		}
		kept = append(kept, previous)
	}
	setupKey.Status.PreviousSetupKeys = kept
	return nil
}

func (r *SetupKeyReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, setupKey *nbv1alpha1.SetupKey) (ctrl.Result, error) {
	setupKeyIDs := make([]string, 0, 1+len(setupKey.Status.PreviousSetupKeys))
	setupKeyIDs = append(setupKeyIDs, setupKey.Status.SetupKeyID)
	for _, previous := range setupKey.Status.PreviousSetupKeys {
		setupKeyIDs = append(setupKeyIDs, previous.SetupKeyID)
	}
	for _, setupKeyID := range setupKeyIDs {
		if setupKeyID == "" {
			continue
		}
		err := r.Netbird.SetupKeys.Delete(ctx, setupKeyID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	controllerutil.RemoveFinalizer(setupKey, k8sutil.Finalizer("setupkey"))
	err := sp.Patch(ctx, setupKey)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *SetupKeyReconciler) now() time.Time {
	if r.Clock == nil {
		return time.Now()
	}
	return r.Clock.Now()
}

// renewAt returns when a setup key that expires at the given time is due for
// renewal, and false if it is never renewed.
func renewAt(setupKey *nbv1alpha1.SetupKey, expires time.Time) (time.Time, bool) {
	renewBefore := setupKey.Spec.RenewBefore
	duration := setupKey.Spec.Duration
	// The API refuses a renewBefore that is not at least a minute and a tenth of
	// duration shorter than duration, as every new key would be due for renewal
	// about as soon as it is created and the replaced keys would pile up.
	if renewBefore == nil || duration == nil || renewBefore.Duration >= duration.Duration || expires.IsZero() {
		return time.Time{}, false
	}
	return expires.Add(-renewBefore.Duration), true
}

// renewalDue reports whether a setup key that expires at the given time is due
// for renewal.
func renewalDue(setupKey *nbv1alpha1.SetupKey, expires, now time.Time) bool {
	at, ok := renewAt(setupKey, expires)
	return ok && !now.Before(at)
}

// requeueAfter returns how long to wait before the setup key is next due for
// renewal, it or a replaced key is due to expire, or the resync interval
// elapses, whichever comes first. A key is only replaced or deleted once NetBird
// reports it expired, so one that is past its expiry by the operator's clock is
// checked again after a short while.
func requeueAfter(setupKey *nbv1alpha1.SetupKey, expires, now time.Time) time.Duration {
	candidates := []time.Time{now.Add(setupKeyResyncInterval)}
	if !expires.IsZero() {
		candidates = append(candidates, expires)
	}
	if at, ok := renewAt(setupKey, expires); ok {
		candidates = append(candidates, at)
	}
	for _, previous := range setupKey.Status.PreviousSetupKeys {
		candidates = append(candidates, previous.ExpiresAt.Time)
	}
	next := slices.MinFunc(candidates, time.Time.Compare)
	if !next.After(now) {
		return setupKeyRetryInterval
	}
	return next.Sub(now)
}

func (r *SetupKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.SetupKey{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
