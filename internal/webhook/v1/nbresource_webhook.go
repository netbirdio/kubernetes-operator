package v1

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/controller"
)

// nolint:unused
// log is for logging in this package.
var nbresourcelog = logf.Log.WithName("nbresource-resource")

// SetupNBResourceWebhookWithManager registers the webhook for NBResource in the manager.
func SetupNBResourceWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&netbirdiov1.NBResource{}).
		WithValidator(&NBResourceCustomValidator{client: mgr.GetClient()}).
		Complete()
}

// NBResourceCustomValidator struct is responsible for validating the NBResource resource
// when it is created, updated, or deleted.
type NBResourceCustomValidator struct {
	client client.Client
}

var _ webhook.CustomValidator = &NBResourceCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type NBResource.
func (v *NBResourceCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type NBResource.
func (v *NBResourceCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NBResource.
func (v *NBResourceCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	nbresource, ok := obj.(*netbirdiov1.NBResource)
	if !ok {
		return nil, fmt.Errorf("expected a NBResource object but got %T", obj)
	}
	nbresourcelog.Info("Validation for NBResource upon deletion", "name", nbresource.GetName())

	var svc corev1.Service
	err := v.client.Get(ctx, types.NamespacedName{Namespace: nbresource.Namespace, Name: nbresource.Name}, &svc)
	if errors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if _, ok := svc.Annotations[controller.ServiceExposeAnnotation]; ok && svc.DeletionTimestamp == nil {
		return nil, fmt.Errorf("service %s/%s still has netbird.io/expose annotation", svc.Namespace, svc.Name)
	}

	return nil, nil
}
