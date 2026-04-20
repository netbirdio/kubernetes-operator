package netbirdutil

import (
	"context"
	"fmt"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

func GetGroupIDs(ctx context.Context, k8sClient client.Client, nbClient *netbird.Client, refs []nbv1alpha1.ResourceReference, namespace string) ([]string, error) {
	groupIDs := []string{}
	for _, ref := range refs {
		switch {
		case ref.ID != nil:
			_, err := nbClient.Groups.Get(ctx, *ref.ID)
			if err != nil {
				return nil, err
			}
			groupIDs = append(groupIDs, *ref.ID)
		case ref.LocalRef != nil:
			group := nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.LocalRef.Name,
					Namespace: namespace,
				},
			}
			err := k8sClient.Get(ctx, client.ObjectKeyFromObject(&group), &group)
			if err != nil {
				return nil, err
			}
			if group.Status.GroupID == "" {
				return nil, fmt.Errorf("group %s in groups list is not ready", group.Name)
			}
			groupIDs = append(groupIDs, group.Status.GroupID)
		}
	}
	return groupIDs, nil
}
