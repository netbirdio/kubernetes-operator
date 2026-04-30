package v1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

// nolint:unused
// log is for logging in this package.
var nbgrouplog = logf.Log.WithName("nbgroup-resource")

// SetupNBGroupWebhookWithManager registers the webhook for NBGroup in the manager.
func SetupNBGroupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &nbv1.NBGroup{}).
		WithValidator(&NBGroupCustomValidator{client: mgr.GetClient()}).
		Complete()
}

// NBGroupCustomValidator struct is responsible for validating the NBGroup resource
// when it is created, updated, or deleted.
type NBGroupCustomValidator struct {
	client client.Client
}

var _ admission.Validator[*nbv1.NBGroup] = &NBGroupCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type NBGroup.
func (v *NBGroupCustomValidator) ValidateCreate(ctx context.Context, group *nbv1.NBGroup) (admission.Warnings, error) {
	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type NBGroup.
func (v *NBGroupCustomValidator) ValidateUpdate(ctx context.Context, old, new *nbv1.NBGroup) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NBGroup.
func (v *NBGroupCustomValidator) ValidateDelete(ctx context.Context, nbgroup *nbv1.NBGroup) (admission.Warnings, error) {
	nbgrouplog.Info("Validation for NBGroup upon deletion", "name", nbgroup.GetName())

	for _, o := range nbgroup.OwnerReferences {
		if o.Kind == (&nbv1.NBResource{}).Kind {
			var nbResource nbv1.NBResource
			err := v.client.Get(ctx, types.NamespacedName{Namespace: nbgroup.Namespace, Name: o.Name}, &nbResource)
			if err != nil && !errors.IsNotFound(err) {
				return nil, err
			}
			if err == nil && nbResource.DeletionTimestamp == nil {
				return nil, fmt.Errorf("group attached to NBResource %s/%s", nbgroup.Namespace, o.Name)
			}
		}
		if o.Kind == (&nbv1.NBRoutingPeer{}).Kind {
			var nbResource nbv1.NBRoutingPeer
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
