// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

var _ = Describe("SetupKey Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var controllerReconciler *SetupKeyReconciler
		var clock *testing.FakePassiveClock
		// start is whole seconds because status.expiresAt is a metav1.Time, which
		// drops anything finer, and the tests compare it with times derived from
		// start.
		start := time.Now().Truncate(time.Second)
		nn := client.ObjectKey{
			Name:      "test-resource",
			Namespace: "default",
		}

		BeforeEach(func() {
			clock = testing.NewFakePassiveClock(start)
			controllerReconciler = &SetupKeyReconciler{
				Client:  k8sClient,
				Netbird: netbirdmock.Client(netbirdmock.WithClock(clock)),
				Clock:   clock,
			}
		})

		// reconcileAt reconciles the SetupKey at the given time after start and
		// returns it as it stands afterwards, with when it asked to be requeued.
		reconcileAt := func(offset time.Duration) (*nbv1alpha1.SetupKey, time.Duration) {
			GinkgoHelper()
			clock.SetTime(start.Add(offset))
			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			setupKey := &nbv1alpha1.SetupKey{}
			Expect(k8sClient.Get(ctx, nn, setupKey)).To(Succeed())
			return setupKey, result.RequeueAfter
		}

		// secretKey returns the setup key stored in the SetupKey's Secret.
		secretKey := func(setupKey *nbv1alpha1.SetupKey) string {
			GinkgoHelper()
			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: setupKey.SecretName(), Namespace: nn.Namespace}, secret)).To(Succeed())
			return string(secret.Data[SetupKeySecretKey])
		}

		// serverKey returns the setup key with the given ID from NetBird, or nil
		// if it does not exist.
		serverKey := func(id string) *api.SetupKey {
			GinkgoHelper()
			key, err := controllerReconciler.Netbird.SetupKeys.Get(ctx, id)
			if netbird.IsNotFound(err) {
				return nil
			}
			Expect(err).NotTo(HaveOccurred())
			return key
		}

		// previousIDs returns the IDs in the SetupKey's status.previousSetupKeys.
		previousIDs := func(setupKey *nbv1alpha1.SetupKey) []string {
			ids := make([]string, 0, len(setupKey.Status.PreviousSetupKeys))
			for _, previous := range setupKey.Status.PreviousSetupKeys {
				ids = append(ids, previous.SetupKeyID)
			}
			return ids
		}

		// revoke revokes the setup key with the given ID on NetBird.
		revoke := func(id string) {
			GinkgoHelper()
			_, err := controllerReconciler.Netbird.SetupKeys.Update(ctx, id, api.PutApiSetupKeysKeyIdJSONRequestBody{Revoked: true})
			Expect(err).NotTo(HaveOccurred())
		}

		// createGroup creates a group on NetBird and returns its ID.
		createGroup := func(name string) string {
			GinkgoHelper()
			group, err := controllerReconciler.Netbird.Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: name})
			Expect(err).NotTo(HaveOccurred())
			return group.Id
		}

		// setSpecField changes one field of the SetupKey's spec.
		setSpecField := func(field string, value any) {
			GinkgoHelper()
			setupKey := &unstructured.Unstructured{}
			setupKey.SetGroupVersionKind(nbv1alpha1.GroupVersion.WithKind("SetupKey"))
			Expect(k8sClient.Get(ctx, nn, setupKey)).To(Succeed())
			Expect(unstructured.SetNestedField(setupKey.Object, value, "spec", field)).To(Succeed())
			Expect(k8sClient.Update(ctx, setupKey)).To(Succeed())
		}

		AfterEach(func() {
			setupKey := &nbv1alpha1.SetupKey{}
			err := k8sClient.Get(ctx, nn, setupKey)
			if kerrors.IsNotFound(err) {
				return
			}
			Expect(err).ToNot(HaveOccurred())
			Expect(k8sClient.Delete(ctx, setupKey)).To(Succeed())
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).ToNot(HaveOccurred())
		})

		It("creates a secret containing the setup key", func() {
			setupKey := &nbv1alpha1.SetupKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.SetupKeySpec{
					Name: "test",
				},
			}
			Expect(k8sClient.Create(ctx, setupKey)).To(Succeed())
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, nn, setupKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(setupKey.Status.ObservedGeneration).To(Equal(setupKey.Generation))
			Expect(setupKey.Status.SetupKeyID).NotTo(BeEmpty())

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      setupKey.SecretName(),
					Namespace: "default",
				},
			}
			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(secret), secret)
			Expect(err).NotTo(HaveOccurred())

			resp, err := controllerReconciler.Netbird.SetupKeys.Get(ctx, setupKey.Status.SetupKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(secret.Data[SetupKeySecretKey])).To(Equal(resp.Key))
		})

		It("creates a new setup key when the secret is deleted", func() {
			setupKey := &nbv1alpha1.SetupKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.SetupKeySpec{
					Name: "test",
				},
			}
			Expect(k8sClient.Create(ctx, setupKey)).To(Succeed())
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			firstSetupKey := nbv1alpha1.SetupKey{}
			err = k8sClient.Get(ctx, nn, &firstSetupKey)
			Expect(err).NotTo(HaveOccurred())

			firstSecret := corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      firstSetupKey.SecretName(),
					Namespace: nn.Namespace,
				},
			}
			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(&firstSecret), &firstSecret)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Delete(ctx, &firstSecret)).To(Succeed())

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			secondSetupKey := nbv1alpha1.SetupKey{}
			err = k8sClient.Get(ctx, nn, &secondSetupKey)
			Expect(err).NotTo(HaveOccurred())

			secondSecret := corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secondSetupKey.SecretName(),
					Namespace: nn.Namespace,
				},
			}
			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(&secondSecret), &secondSecret)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Delete(ctx, &secondSecret)).To(Succeed())

			Expect(firstSetupKey.Status.SetupKeyID).ToNot(Equal(secondSetupKey.Status.SetupKeyID))
			Expect(firstSecret.Data[SetupKeySecretKey]).ToNot(BeEquivalentTo(secondSecret.Data[SetupKeySecretKey]))
			Expect(serverKey(firstSetupKey.Status.SetupKeyID)).To(BeNil(), "without renewBefore the replaced key is deleted at once")
			Expect(secondSetupKey.Status.PreviousSetupKeys).To(BeEmpty())
		})

		It("renews the setup key within renewBefore of its expiry and keeps the old key until it expires", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
			})).To(Succeed())

			setupKey, requeue := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			Expect(firstID).NotTo(BeEmpty())
			Expect(setupKey.Status.ExpiresAt).NotTo(BeNil())
			Expect(setupKey.Status.ExpiresAt.Time).To(BeTemporally("==", start.Add(2*time.Hour)))
			Expect(requeue).To(Equal(15 * time.Minute))
			firstKey := secretKey(setupKey)

			By("not renewing it before the window opens")
			setupKey, requeue = reconcileAt(89 * time.Minute)
			Expect(setupKey.Status.SetupKeyID).To(Equal(firstID))
			Expect(setupKey.Status.PreviousSetupKeys).To(BeEmpty())
			Expect(secretKey(setupKey)).To(Equal(firstKey))
			Expect(requeue).To(Equal(time.Minute), "requeued for when the window opens")

			By("renewing it once the window opens")
			setupKey, requeue = reconcileAt(90 * time.Minute)
			secondID := setupKey.Status.SetupKeyID
			Expect(secondID).NotTo(Equal(firstID))
			Expect(setupKey.Status.ExpiresAt.Time).To(BeTemporally("==", start.Add(90*time.Minute+2*time.Hour)))
			Expect(secretKey(setupKey)).To(Equal(serverKey(secondID).Key))
			Expect(setupKey.Status.PreviousSetupKeys).To(HaveExactElements(nbv1alpha1.PreviousSetupKey{
				SetupKeyID: firstID,
				ExpiresAt:  metav1.NewTime(start.Add(2 * time.Hour)),
			}))
			Expect(serverKey(firstID)).NotTo(BeNil(), "the replaced key is kept while it is valid")
			Expect(requeue).To(Equal(15 * time.Minute))

			By("keeping the replaced key until it expires")
			setupKey, requeue = reconcileAt(119 * time.Minute)
			Expect(setupKey.Status.SetupKeyID).To(Equal(secondID))
			Expect(setupKey.Status.PreviousSetupKeys).To(HaveLen(1))
			Expect(serverKey(firstID)).NotTo(BeNil())
			Expect(requeue).To(Equal(time.Minute), "requeued for when the replaced key expires")

			By("keeping the replaced key while NetBird still reports it valid")
			setupKey, requeue = reconcileAt(2 * time.Hour)
			Expect(setupKey.Status.PreviousSetupKeys).To(HaveLen(1))
			Expect(serverKey(firstID)).NotTo(BeNil())
			Expect(requeue).To(Equal(setupKeyRetryInterval), "checked again shortly")

			By("deleting the replaced key once NetBird reports it expired")
			setupKey, requeue = reconcileAt(2*time.Hour + time.Second)
			Expect(setupKey.Status.SetupKeyID).To(Equal(secondID))
			Expect(setupKey.Status.PreviousSetupKeys).To(BeEmpty())
			Expect(serverKey(firstID)).To(BeNil())
			Expect(serverKey(secondID)).NotTo(BeNil())
			Expect(requeue).To(Equal(15 * time.Minute))
		})

		It("keeps several replaced keys when renewBefore is longer than half the duration", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "90m",
			})).To(Succeed())

			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			setupKey, requeue := reconcileAt(30 * time.Minute)
			secondID := setupKey.Status.SetupKeyID
			Expect(secondID).NotTo(Equal(firstID))
			Expect(previousIDs(setupKey)).To(Equal([]string{firstID}))
			Expect(requeue).To(Equal(15 * time.Minute))

			setupKey, requeue = reconcileAt(60 * time.Minute)
			thirdID := setupKey.Status.SetupKeyID
			Expect(thirdID).NotTo(BeElementOf(firstID, secondID))
			Expect(previousIDs(setupKey)).To(Equal([]string{firstID, secondID}), "both replaced keys are kept")
			Expect(serverKey(firstID)).NotTo(BeNil())
			Expect(serverKey(secondID)).NotTo(BeNil())
			Expect(requeue).To(Equal(15 * time.Minute))

			By("deleting only the replaced key that has expired")
			setupKey, _ = reconcileAt(2*time.Hour + time.Second)
			Expect(setupKey.Status.SetupKeyID).NotTo(BeElementOf(firstID, secondID, thirdID), "the third key was due for renewal too")
			Expect(previousIDs(setupKey)).To(Equal([]string{secondID, thirdID}))
			Expect(serverKey(firstID)).To(BeNil())
			Expect(serverKey(secondID)).NotTo(BeNil())
			Expect(serverKey(thirdID)).NotTo(BeNil())
		})

		It("keeps a setup key still valid on the server when its Secret is lost", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
			})).To(Succeed())
			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID

			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: setupKey.SecretName(), Namespace: nn.Namespace}}
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())

			setupKey, _ = reconcileAt(10 * time.Minute)
			secondID := setupKey.Status.SetupKeyID
			Expect(secondID).NotTo(Equal(firstID))
			Expect(secretKey(setupKey)).To(Equal(serverKey(secondID).Key))
			Expect(setupKey.Status.PreviousSetupKeys).To(HaveExactElements(nbv1alpha1.PreviousSetupKey{
				SetupKeyID: firstID,
				ExpiresAt:  metav1.NewTime(start.Add(2 * time.Hour)),
			}))
			Expect(serverKey(firstID)).NotTo(BeNil(), "whatever copied the Secret may still hold the key")
		})

		It("replaces a revoked setup key at once", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
			})).To(Succeed())
			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID

			revoke(firstID)
			setupKey, _ = reconcileAt(10 * time.Minute)
			Expect(setupKey.Status.SetupKeyID).NotTo(Equal(firstID))
			Expect(setupKey.Status.PreviousSetupKeys).To(BeEmpty())
			Expect(serverKey(firstID)).To(BeNil(), "nothing can enroll with a revoked key, so it is not kept")
		})

		It("updates the auto groups of the replaced keys", func() {
			firstGroup := createGroup("first")
			secondGroup := createGroup("second")
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
				"autoGroups":  []any{map[string]any{"id": firstGroup}},
			})).To(Succeed())
			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			setupKey, _ = reconcileAt(90 * time.Minute)
			secondID := setupKey.Status.SetupKeyID
			Expect(previousIDs(setupKey)).To(Equal([]string{firstID}))
			Expect(serverKey(firstID).AutoGroups).To(ConsistOf(firstGroup))

			setSpecField("autoGroups", []any{map[string]any{"id": secondGroup}})
			setupKey, _ = reconcileAt(91 * time.Minute)
			Expect(setupKey.Status.ObservedGeneration).To(Equal(setupKey.Generation))
			Expect(serverKey(secondID).AutoGroups).To(ConsistOf(secondGroup))
			Expect(serverKey(firstID).AutoGroups).To(ConsistOf(secondGroup), "a peer enrolling with the replaced key lands in the current groups")
		})

		It("deletes a replaced key revoked behind the operator's back at once", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
			})).To(Succeed())
			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			setupKey, _ = reconcileAt(90 * time.Minute)
			secondID := setupKey.Status.SetupKeyID
			Expect(previousIDs(setupKey)).To(Equal([]string{firstID}))

			revoke(firstID)
			setupKey, _ = reconcileAt(91 * time.Minute)
			Expect(setupKey.Status.SetupKeyID).To(Equal(secondID))
			Expect(setupKey.Status.PreviousSetupKeys).To(BeEmpty())
			Expect(serverKey(firstID)).To(BeNil())
		})

		It("deletes a renewed key the Secret could not store instead of keeping it", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
			})).To(Succeed())
			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			firstKey := secretKey(setupKey)

			By("failing to write the Secret at renewal")
			// client.NewWithWatch does not honor Options.FieldOwner, unlike client.New.
			watchClient, err := client.NewWithWatch(cfg, client.Options{Scheme: scheme.Scheme})
			Expect(err).NotTo(HaveOccurred())
			applyFails := true
			controllerReconciler.Client = client.WithFieldOwner(interceptor.NewClient(watchClient, interceptor.Funcs{
				Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					if applyFails {
						return errors.New("apply failed")
					}
					return c.Apply(ctx, obj, opts...)
				},
			}), "netbird-operator")
			clock.SetTime(start.Add(90 * time.Minute))
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).To(MatchError("apply failed"))
			Expect(k8sClient.Get(ctx, nn, setupKey)).To(Succeed())
			undeliveredID := setupKey.Status.SetupKeyID
			Expect(undeliveredID).NotTo(Equal(firstID), "the status records the key before the Secret is written")
			Expect(serverKey(undeliveredID)).To(BeNil(), "the key the Secret does not hold is deleted")
			Expect(secretKey(setupKey)).To(Equal(firstKey))
			Expect(previousIDs(setupKey)).To(Equal([]string{firstID}))

			By("renewing with the next key once the Secret can be written")
			applyFails = false
			setupKey, _ = reconcileAt(91 * time.Minute)
			Expect(setupKey.Status.SetupKeyID).NotTo(BeElementOf(firstID, undeliveredID))
			Expect(secretKey(setupKey)).To(Equal(serverKey(setupKey.Status.SetupKeyID).Key))
			Expect(previousIDs(setupKey)).To(Equal([]string{firstID}), "the undelivered key is not kept as a replaced key")
		})

		It("resumes a renewal interrupted before the Secret was updated", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
			})).To(Succeed())
			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			firstKey := secretKey(setupKey)

			// A renewal records the new key in the status before it writes the
			// Secret. Stand in for one that got no further.
			clock.SetTime(start.Add(90 * time.Minute))
			created, err := controllerReconciler.Netbird.SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
				Name: "test", Type: "reusable", ExpiresIn: int((2 * time.Hour).Seconds()),
			})
			Expect(err).NotTo(HaveOccurred())
			setupKey.Status.SetupKeyID = created.Id
			setupKey.Status.PreviousSetupKeys = []nbv1alpha1.PreviousSetupKey{{
				SetupKeyID: firstID,
				ExpiresAt:  metav1.NewTime(start.Add(2 * time.Hour)),
			}}
			Expect(k8sClient.Status().Update(ctx, setupKey)).To(Succeed())

			setupKey, _ = reconcileAt(90 * time.Minute)
			thirdID := setupKey.Status.SetupKeyID
			Expect(thirdID).NotTo(BeElementOf(firstID, created.Id))
			Expect(secretKey(setupKey)).NotTo(Equal(firstKey))
			Expect(secretKey(setupKey)).To(Equal(serverKey(thirdID).Key))
			Expect(previousIDs(setupKey)).To(Equal([]string{firstID, created.Id}), "both keys are still valid and are kept")
			Expect(serverKey(firstID)).NotTo(BeNil())
			Expect(serverKey(created.Id)).NotTo(BeNil())
		})

		It("only replaces a setup key without renewBefore once NetBird reports it expired", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":      "test",
				"ephemeral": false,
				"duration":  "2h",
			})).To(Succeed())

			setupKey, requeue := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			Expect(requeue).To(Equal(15 * time.Minute))

			setupKey, requeue = reconcileAt(119 * time.Minute)
			Expect(setupKey.Status.SetupKeyID).To(Equal(firstID))
			Expect(requeue).To(Equal(time.Minute), "requeued for when the key expires")

			setupKey, requeue = reconcileAt(2 * time.Hour)
			Expect(setupKey.Status.SetupKeyID).To(Equal(firstID), "NetBird does not report it expired yet")
			Expect(requeue).To(Equal(setupKeyRetryInterval))

			setupKey, requeue = reconcileAt(2*time.Hour + time.Second)
			Expect(setupKey.Status.SetupKeyID).NotTo(Equal(firstID))
			Expect(setupKey.Status.PreviousSetupKeys).To(BeEmpty())
			Expect(serverKey(firstID)).To(BeNil(), "an expired key is deleted at once")
			Expect(setupKey.Status.ExpiresAt.Time).To(BeTemporally("==", start.Add(4*time.Hour+time.Second)))
			Expect(requeue).To(Equal(15 * time.Minute))
		})

		It("deletes the replaced setup keys along with the SetupKey", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
			})).To(Succeed())
			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			setupKey, _ = reconcileAt(90 * time.Minute)
			secondID := setupKey.Status.SetupKeyID
			Expect(setupKey.Status.PreviousSetupKeys).To(HaveLen(1))

			Expect(k8sClient.Delete(ctx, setupKey)).To(Succeed())
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			Expect(serverKey(firstID)).To(BeNil())
			Expect(serverKey(secondID)).To(BeNil())
		})

		DescribeTable("validates renewBefore against duration",
			func(spec map[string]any, wantErr string) {
				spec["name"] = "test"
				spec["ephemeral"] = false
				err := createSetupKeyFromSpec(ctx, nn, spec)
				if wantErr == "" {
					Expect(err).NotTo(HaveOccurred())
					return
				}
				Expect(kerrors.IsInvalid(err)).To(BeTrue(), "unexpected error: %v", err)
				Expect(err.Error()).To(ContainSubstring(wantErr))
			},
			Entry("renewBefore shorter than duration", map[string]any{"duration": "2h", "renewBefore": "1.5h"}, ""),
			Entry("renewBefore a minute and a tenth shorter than duration", map[string]any{"duration": "10m", "renewBefore": "9m"}, ""),
			Entry("renewBefore nine tenths of duration", map[string]any{"duration": "10h", "renewBefore": "9h"}, ""),
			Entry("renewBefore in seconds", map[string]any{"duration": "2h", "renewBefore": "30s"}, ""),
			Entry("durations as a typed client writes them", map[string]any{"duration": "2h0m0s", "renewBefore": "30m0s"}, ""),
			Entry("renewBefore without duration", map[string]any{"renewBefore": "30m"}, "renewBefore requires duration"),
			Entry("renewBefore less than a minute shorter than duration", map[string]any{"duration": "2h", "renewBefore": "1h59m30s"}, "renewBefore must be at least 1m shorter than duration"),
			Entry("renewBefore more than nine tenths of duration", map[string]any{"duration": "24h", "renewBefore": "1439m"}, "renewBefore must be at most nine tenths of duration"),
			Entry("renewBefore equal to duration", map[string]any{"duration": "2h", "renewBefore": "120m"}, "renewBefore must be at least 1m shorter than duration"),
			Entry("renewBefore longer than duration", map[string]any{"duration": "2h", "renewBefore": "3h"}, "renewBefore must be at least 1m shorter than duration"),
			Entry("renewBefore in days", map[string]any{"duration": "48h", "renewBefore": "1d"}, "spec.renewBefore"),
		)

		It("accepts durations from a typed client", func() {
			setupKey := &nbv1alpha1.SetupKey{
				ObjectMeta: metav1.ObjectMeta{Name: nn.Name, Namespace: nn.Namespace},
				Spec: nbv1alpha1.SetupKeySpec{
					Name:        "test",
					Duration:    &metav1.Duration{Duration: 2 * time.Hour},
					RenewBefore: &metav1.Duration{Duration: 30 * time.Minute},
				},
			}
			Expect(k8sClient.Create(ctx, setupKey)).To(Succeed())
			setupKey, _ = reconcileAt(0)
			Expect(setupKey.Status.ExpiresAt.Time).To(BeTemporally("==", start.Add(2*time.Hour)))
		})

		It("renews at the new time when renewBefore changes", func() {
			Expect(createSetupKeyFromSpec(ctx, nn, map[string]any{
				"name":        "test",
				"ephemeral":   false,
				"duration":    "2h",
				"renewBefore": "30m",
			})).To(Succeed())
			setupKey, _ := reconcileAt(0)
			firstID := setupKey.Status.SetupKeyID
			setSpecField("renewBefore", "1h")

			By("requeuing for the new renewal time")
			setupKey, requeue := reconcileAt(59 * time.Minute)
			Expect(setupKey.Status.ObservedGeneration).To(Equal(setupKey.Generation))
			Expect(setupKey.Status.SetupKeyID).To(Equal(firstID))
			Expect(requeue).To(Equal(time.Minute), "requeued for when the new window opens")

			By("renewing at the new renewal time")
			setupKey, _ = reconcileAt(60 * time.Minute)
			Expect(setupKey.Status.SetupKeyID).NotTo(Equal(firstID))
			Expect(previousIDs(setupKey)).To(Equal([]string{firstID}))
		})
	})
})

// createSetupKeyFromSpec creates a SetupKey with the given spec. It is written
// untyped so the validation cases can pass the raw strings.
func createSetupKeyFromSpec(ctx context.Context, nn client.ObjectKey, spec map[string]any) error {
	setupKey := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	setupKey.SetGroupVersionKind(nbv1alpha1.GroupVersion.WithKind("SetupKey"))
	setupKey.SetName(nn.Name)
	setupKey.SetNamespace(nn.Namespace)
	return k8sClient.Create(ctx, setupKey)
}
