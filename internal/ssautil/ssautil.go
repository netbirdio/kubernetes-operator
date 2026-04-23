package ssautil

import (
	"k8s.io/apimachinery/pkg/runtime"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

func ControllerReference(owner client.Object, scheme *runtime.Scheme) (*metav1ac.OwnerReferenceApplyConfiguration, error) {
	gvk, err := apiutil.GVKForObject(owner, scheme)
	if err != nil {
		return nil, err
	}
	return metav1ac.OwnerReference().
		WithAPIVersion(gvk.GroupVersion().String()).
		WithKind(gvk.Kind).
		WithName(owner.GetName()).
		WithUID(owner.GetUID()).
		WithController(true).
		WithBlockOwnerDeletion(true), nil
}

func OwnerReference(owner client.Object, scheme *runtime.Scheme) (*metav1ac.OwnerReferenceApplyConfiguration, error) {
	gvk, err := apiutil.GVKForObject(owner, scheme)
	if err != nil {
		return nil, err
	}
	return metav1ac.OwnerReference().
		WithAPIVersion(gvk.GroupVersion().String()).
		WithKind(gvk.Kind).
		WithName(owner.GetName()).
		WithUID(owner.GetUID()).
		WithController(false).
		WithBlockOwnerDeletion(false), nil
}
