package v1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	netbird "github.com/netbirdio/netbird/management/client/rest"
)

// nolint:unused
// log is for logging in this package.
var nbgrouplog = logf.Log.WithName("nbgroup-resource")

// SetupNBGroupWebhookWithManager registers the webhook for NBGroup in the manager.
func SetupNBGroupWebhookWithManager(mgr ctrl.Manager, managementURL, apiKey string) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&netbirdiov1.NBGroup{}).
		WithValidator(&NBGroupCustomValidator{netbird: netbird.New(managementURL, apiKey), client: mgr.GetClient()}).
		Complete()
}

// NBGroupCustomValidator struct is responsible for validating the NBGroup resource
// when it is created, updated, or deleted.
type NBGroupCustomValidator struct {
	netbird *netbird.Client
	client  client.Client
}

var _ webhook.CustomValidator = &NBGroupCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type NBGroup.
func (v *NBGroupCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type NBGroup.
func (v *NBGroupCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NBGroup.
func (v *NBGroupCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	nbgroup, ok := obj.(*netbirdiov1.NBGroup)
	if !ok {
		return nil, fmt.Errorf("expected a NBGroup object but got %T", obj)
	}
	nbgrouplog.Info("Validation for NBGroup upon deletion", "name", nbgroup.GetName())

	for _, o := range nbgroup.OwnerReferences {
		if o.Kind == (&netbirdiov1.NBResource{}).Kind {
			var nbResource netbirdiov1.NBResource
			err := v.client.Get(ctx, types.NamespacedName{Namespace: nbgroup.Namespace, Name: o.Name}, &nbResource)
			if err != nil && !errors.IsNotFound(err) {
				return nil, err
			}
			if err == nil && nbResource.DeletionTimestamp == nil {
				return nil, fmt.Errorf("group attached to NBResource %s/%s", nbgroup.Namespace, o.Name)
			}
		}
		if o.Kind == (&netbirdiov1.NBRoutingPeer{}).Kind {
			var nbResource netbirdiov1.NBRoutingPeer
			err := v.client.Get(ctx, types.NamespacedName{Namespace: nbgroup.Namespace, Name: o.Name}, &nbResource)
			if err != nil && !errors.IsNotFound(err) {
				return nil, err
			}
			if err == nil && nbResource.DeletionTimestamp == nil {
				return nil, fmt.Errorf("group attached to NBRoutingPeer %s/%s", nbgroup.Namespace, o.Name)
			}
		}
	}

	return nil, nil
}
