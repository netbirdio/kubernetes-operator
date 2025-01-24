package v1

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/google/uuid"
	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

// nolint:unused
// log is for logging in this package.
var nbsetupkeylog = logf.Log.WithName("nbsetupkey-resource")

// SetupNBSetupKeyWebhookWithManager registers the webhook for NBSetupKey in the manager.
func SetupNBSetupKeyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&netbirdiov1.NBSetupKey{}).
		WithValidator(&NBSetupKeyCustomValidator{client: mgr.GetClient()}).
		Complete()
}

// NBSetupKeyCustomValidator struct is responsible for validating the NBSetupKey resource
// when it is created, updated, or deleted.
type NBSetupKeyCustomValidator struct {
	client client.Client
}

var _ webhook.CustomValidator = &NBSetupKeyCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type NBSetupKey.
func (v *NBSetupKeyCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	nbSetupKey, ok := obj.(*netbirdiov1.NBSetupKey)
	if !ok {
		return nil, fmt.Errorf("expected a NBSetupKey object but got %T", obj)
	}
	nbsetupkeylog.Info("Validating NBSetupKey", "namespace", nbSetupKey.Namespace, "name", nbSetupKey.Name)

	if nbSetupKey.Spec.SecretKeyRef.Name == "" {
		return nil, fmt.Errorf("spec.secretKeyRef.name is required")
	}

	if nbSetupKey.Spec.SecretKeyRef.Key == "" {
		return nil, fmt.Errorf("spec.secretKeyRef.key is required")
	}

	var secret corev1.Secret
	err := v.client.Get(ctx, types.NamespacedName{Namespace: nbSetupKey.Namespace, Name: nbSetupKey.Spec.SecretKeyRef.Name}, &secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return admission.Warnings{fmt.Sprintf("secret %s/%s not found", nbSetupKey.Namespace, nbSetupKey.Spec.SecretKeyRef.Name)}, nil
		}
		return nil, err
	}

	uuidBytes, ok := secret.Data[nbSetupKey.Spec.SecretKeyRef.Key]
	if !ok {
		return admission.Warnings{fmt.Sprintf("key %s in secret %s/%s not found", nbSetupKey.Spec.SecretKeyRef.Key, nbSetupKey.Namespace, nbSetupKey.Spec.SecretKeyRef.Name)}, nil
	}

	_, err = uuid.Parse(string(uuidBytes))
	if err != nil {
		return admission.Warnings{fmt.Sprintf("setupkey %s in secret %s/%s is not a valid setup key", nbSetupKey.Spec.SecretKeyRef.Key, nbSetupKey.Namespace, nbSetupKey.Spec.SecretKeyRef.Name)}, nil
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type NBSetupKey.
func (v *NBSetupKeyCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	return v.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NBSetupKey.
func (v *NBSetupKeyCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	nbSetupKey, ok := obj.(*netbirdiov1.NBSetupKey)
	if !ok {
		return nil, fmt.Errorf("expected a NBSetupKey object but got %T", obj)
	}
	nbsetupkeylog.Info("Validating NBSetupKey deletion", "namespace", nbSetupKey.Namespace, "name", nbSetupKey.Name)

	var pods corev1.PodList
	err := v.client.List(ctx, &pods, client.InNamespace(nbSetupKey.Namespace))
	if err != nil {
		return nil, err
	}

	//nolint:prealloc
	var invalidPods []string
	for _, p := range pods.Items {
		// If annotation doesn't exist, or doesn't match NBSetupKey being deleted, ignore
		if v, ok := p.Annotations[setupKeyAnnotation]; !ok || v != nbSetupKey.Name {
			continue
		}
		invalidPods = append(invalidPods, p.Name)
	}

	if len(invalidPods) > 0 {
		return nil, fmt.Errorf("NBSetupKey is in-use by %d pods: %s", len(invalidPods), strings.Join(invalidPods, ","))
	}

	return nil, nil
}
