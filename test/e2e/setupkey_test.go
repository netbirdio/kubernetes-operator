// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// setupKeySecretKey is the Secret key the operator stores a setup key under.
const setupKeySecretKey = "setup-key"

// TestSetupKey checks that a SetupKey ends up on the server as specified, with
// auto-groups given in each of the three ways a reference can be written and an
// expiry that follows spec.duration, that the key in its Secret really enrolls a
// peer into those groups, and that a key revoked behind the operator's back is
// replaced.
func TestSetupKey(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	ns := e.createNamespace(t, "setupkey")

	localGroup := &nbv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: ns},
		Spec:       nbv1alpha1.GroupSpec{Name: "e2e-local-" + rand.String(6)},
	}
	require.NoError(t, e.k8s.Create(t.Context(), localGroup))
	e.waitReady(t, localGroup)
	byName, err := e.nb.Groups.Create(t.Context(), api.PostApiGroupsJSONRequestBody{Name: "e2e-by-name-" + rand.String(6)})
	require.NoError(t, err)
	byID, err := e.nb.Groups.Create(t.Context(), api.PostApiGroupsJSONRequestBody{Name: "e2e-by-id-" + rand.String(6)})
	require.NoError(t, err)
	wantGroups := []string{localGroup.Status.GroupID, byName.Id, byID.Id}

	name := "e2e-key-" + rand.String(6)
	setupKey := &nbv1alpha1.SetupKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: ns},
		Spec: nbv1alpha1.SetupKeySpec{
			Name:                name,
			AllowExtraDnsLabels: true,
			AutoGroups: []nbv1alpha1.GroupReference{
				{LocalRef: &corev1.LocalObjectReference{Name: localGroup.Name}},
				{Name: new(byName.Name)},
				{ID: new(byID.Id)},
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), setupKey))
	e.waitReady(t, setupKey)
	keyID := setupKey.Status.SetupKeyID

	key, err := e.nb.SetupKeys.Get(t.Context(), keyID)
	require.NoError(t, err)
	assert.EqualT(t, name, key.Name, "key name")
	assert.FalseT(t, key.Ephemeral, "ephemeral")
	assert.TrueT(t, key.AllowExtraDnsLabels, "allow extra DNS labels")
	assert.TrueT(t, key.Valid, "key valid")
	assert.ElementsMatch(t, wantGroups, key.AutoGroups, "auto-groups")

	secretValue := e.setupKeySecret(t, setupKey)
	peer := e.enroll(t, secretValue)
	assert.ElementsMatch(t, append([]string{e.allGroupID(t)}, wantGroups...), groupIDs(peer.Groups),
		"a peer enrolled with the key lands in its auto-groups")

	// The key is created from Go, where metav1.Duration marshals 24h as 24h0m0s:
	// what any Go client, the operator's own API types included, sends.
	t.Run("expiry follows spec.duration", func(t *testing.T) {
		expiring := &nbv1alpha1.SetupKey{
			ObjectMeta: metav1.ObjectMeta{Name: "expiring", Namespace: ns},
			Spec: nbv1alpha1.SetupKeySpec{
				Name:     "e2e-expiring-" + rand.String(6),
				Duration: &metav1.Duration{Duration: 24 * time.Hour},
			},
		}
		require.NoError(t, e.k8s.Create(t.Context(), expiring), "create a SetupKey with spec.duration 24h0m0s")
		e.waitReady(t, expiring)
		expiringKey, err := e.nb.SetupKeys.Get(t.Context(), expiring.Status.SetupKeyID)
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(24*time.Hour), expiringKey.Expires, 10*time.Minute, "expiry follows spec.duration")
	})

	t.Run("revoked on the server", func(t *testing.T) {
		_, err := e.nb.SetupKeys.Update(t.Context(), keyID, api.PutApiSetupKeysKeyIdJSONRequestBody{
			AutoGroups: key.AutoGroups,
			Revoked:    true,
		})
		require.NoError(t, err)
		e.touch(t, setupKey)
		require.Eventually(t, func(ctx context.Context) error {
			if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(setupKey), setupKey); err != nil {
				return err
			}
			if setupKey.Status.SetupKeyID == keyID {
				return fmt.Errorf("the revoked key %s was not replaced", keyID)
			}
			return nil
		}, readyTimeout, 2*time.Second)
		requireGone(t, "revoked setup key", keyID, e.nb.SetupKeys.Get)
		keyID = setupKey.Status.SetupKeyID
		replaced, err := e.nb.SetupKeys.Get(t.Context(), keyID)
		require.NoError(t, err)
		assert.TrueT(t, replaced.Valid, "replacement key valid")
		require.Eventually(t, func(ctx context.Context) error {
			secret := &corev1.Secret{}
			if err := e.k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: setupKey.SecretName()}, secret); err != nil {
				return err
			}
			if string(secret.Data[setupKeySecretKey]) == secretValue {
				return fmt.Errorf("Secret %s still holds the revoked key", setupKey.SecretName())
			}
			return nil
		}, readyTimeout, 2*time.Second)
	})

	require.NoError(t, e.k8s.Delete(t.Context(), setupKey))
	e.waitGone(t, setupKey)
	requireGone(t, "setup key", keyID, e.nb.SetupKeys.Get)
}

// setupKeySecret returns the key the operator stored in the SetupKey's Secret.
func (e *environment) setupKeySecret(t *testing.T, setupKey *nbv1alpha1.SetupKey) string {
	t.Helper()
	secret := &corev1.Secret{}
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKey{Namespace: setupKey.Namespace, Name: setupKey.SecretName()}, secret))
	value := string(secret.Data[setupKeySecretKey])
	require.NotEmpty(t, value, "Secret %s has no %s", setupKey.SecretName(), setupKeySecretKey)
	return value
}

// enroll joins a NetBird client container with the setup key and returns the
// peer it registered as.
func (e *environment) enroll(t *testing.T, key string) api.Peer {
	t.Helper()
	hostname := "enrolled-" + rand.String(6)
	client, err := harness.StartClient(t.Context(), e.srv, key, harness.WithClientName(hostname))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := client.Terminate(context.Background()); err != nil {
			t.Logf("terminate %s: %v", hostname, err)
		}
	})

	var peer api.Peer
	require.Eventually(t, func(ctx context.Context) error {
		peers, err := e.nb.Peers.List(ctx)
		if err != nil {
			return err
		}
		idx := slices.IndexFunc(peers, func(p api.Peer) bool { return p.Hostname == hostname })
		if idx == -1 {
			return fmt.Errorf("no peer registered as %s", hostname)
		}
		peer = peers[idx]
		return nil
	}, readyTimeout, 2*time.Second)
	return peer
}

// allGroupID returns the ID of the built-in group every peer is in.
func (e *environment) allGroupID(t *testing.T) string {
	t.Helper()
	all, err := e.nb.Groups.GetByName(t.Context(), "All")
	require.NoError(t, err)
	return all.Id
}
