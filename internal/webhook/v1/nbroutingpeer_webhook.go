package v1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
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
var nbroutingpeerlog = logf.Log.WithName("nbroutingpeer-resource")

// SetupNBRoutingPeerWebhookWithManager registers the webhook for NBRoutingPeer in the manager.
func SetupNBRoutingPeerWebhookWithManager(mgr ctrl.Manager, managementURL, apiKey string) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&netbirdiov1.NBRoutingPeer{}).
		WithValidator(&NBRoutingPeerCustomValidator{netbird: netbird.New(managementURL, apiKey), client: mgr.GetClient()}).
		Complete()
}

// NBRoutingPeerCustomValidator struct is responsible for validating the NBRoutingPeer resource
// when it is created, updated, or deleted.
type NBRoutingPeerCustomValidator struct {
	netbird *netbird.Client
	client  client.Client
}

var _ webhook.CustomValidator = &NBRoutingPeerCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type NBRoutingPeer.
func (v *NBRoutingPeerCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type NBRoutingPeer.
func (v *NBRoutingPeerCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NBRoutingPeer.
func (v *NBRoutingPeerCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	nbroutingpeer, ok := obj.(*netbirdiov1.NBRoutingPeer)
	if !ok {
		return nil, fmt.Errorf("expected a NBRoutingPeer object but got %T", obj)
	}
	nbroutingpeerlog.Info("Validation for NBRoutingPeer upon deletion", "name", nbroutingpeer.GetName())

	if nbroutingpeer.Status.NetworkID == nil {
		return nil, nil
	}

	var nbResources netbirdiov1.NBResourceList
	err := v.client.List(ctx, &nbResources)
	if err != nil {
		return nil, err
	}

	for _, r := range nbResources.Items {
		if r.Spec.NetworkID == *nbroutingpeer.Status.NetworkID {
			err = v.client.Delete(ctx, &r, client.DryRunAll)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", r.Namespace, r.Name, err)
			}
		}
	}

	return nil, nil
}
