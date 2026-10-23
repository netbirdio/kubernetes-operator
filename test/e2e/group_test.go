// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestGroup covers a Group's lifecycle on the server, including the two ways
// the group can drift: deleted or renamed by someone else.
func TestGroup(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	ns := e.createNamespace(t, "group")

	name := "e2e-group-" + rand.String(6)
	group := &nbv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: ns},
		Spec:       nbv1alpha1.GroupSpec{Name: name},
	}
	require.NoError(t, e.k8s.Create(t.Context(), group))
	e.waitReady(t, group)
	id := group.Status.GroupID
	requireGroupName(t, e, id, name)

	t.Run("renamed through the spec", func(t *testing.T) {
		renamed := name + "-renamed"
		require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKeyFromObject(group), group))
		group.Spec.Name = renamed
		require.NoError(t, e.k8s.Update(t.Context(), group))
		e.waitReady(t, group)
		assert.EqualT(t, id, group.Status.GroupID, "renaming recreated the group")
		requireGroupName(t, e, id, renamed)
		name = renamed
	})

	t.Run("renamed on the server", func(t *testing.T) {
		_, err := e.nb.Groups.Update(t.Context(), id, api.PutApiGroupsGroupIdJSONRequestBody{Name: "renamed-behind-the-operator"})
		require.NoError(t, err)
		e.touch(t, group)
		requireGroupName(t, e, id, name)
	})

	t.Run("deleted on the server", func(t *testing.T) {
		require.NoError(t, e.nb.Groups.Delete(t.Context(), id))
		e.touch(t, group)
		require.Eventually(t, func(ctx context.Context) error {
			if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(group), group); err != nil {
				return err
			}
			if group.Status.GroupID == "" || group.Status.GroupID == id {
				return fmt.Errorf("the group was not recreated; status.groupID is %q", group.Status.GroupID)
			}
			return nil
		}, readyTimeout, 2*time.Second)
		id = group.Status.GroupID
		requireGroupName(t, e, id, name)
	})

	require.NoError(t, e.k8s.Delete(t.Context(), group))
	e.waitGone(t, group)
	requireGone(t, "group", id, e.nb.Groups.Get)
}

// requireGroupName waits until the server holds the group under the name.
func requireGroupName(t *testing.T, e *environment, id, name string) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		g, err := e.nb.Groups.Get(ctx, id)
		if err != nil {
			return err
		}
		if g.Name != name {
			return fmt.Errorf("group %s is named %q, want %q", id, g.Name, name)
		}
		return nil
	}, readyTimeout, 2*time.Second)
}
