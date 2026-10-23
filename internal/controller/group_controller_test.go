// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"

	"github.com/fluxcd/pkg/runtime/conditions"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

var _ = Describe("Group Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var controllerReconciler *GroupReconciler
		nn := client.ObjectKey{
			Name:      "test-resource",
			Namespace: "default",
		}

		BeforeEach(func() {
			controllerReconciler = &GroupReconciler{
				Client:  k8sClient,
				Netbird: netbirdmock.Client(),
			}
		})

		AfterEach(func() {
			group := &nbv1alpha1.Group{}
			err := k8sClient.Get(ctx, nn, group)
			if kerrors.IsNotFound(err) {
				return
			}
			Expect(err).ToNot(HaveOccurred())
			Expect(k8sClient.Delete(ctx, group)).To(Succeed())
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).ToNot(HaveOccurred())
		})

		It("ensures a Netbird group exists on reconcile", func() {
			group := &nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.GroupSpec{
					Name: "foobar",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())

			By("creating a group on initial creation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			err = k8sClient.Get(ctx, nn, group)
			Expect(err).NotTo(HaveOccurred())
			Expect(group.Status.ObservedGeneration).To(Equal(group.Generation))
			Expect(group.Status.GroupID).NotTo(BeEmpty())

			By("crerating a new group when deleted from API")
			err = controllerReconciler.Netbird.Groups.Delete(ctx, group.Status.GroupID)
			Expect(err).NotTo(HaveOccurred())
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			newGroup := &nbv1alpha1.Group{}
			err = k8sClient.Get(ctx, nn, newGroup)
			Expect(err).NotTo(HaveOccurred())
			Expect(newGroup.Status.GroupID).NotTo(Equal(group.Status.GroupID))
		})

		It("adopts a Netbird group that already exists with the same name", func() {
			existing, err := controllerReconciler.Netbird.Groups.Create(ctx, api.GroupRequest{Name: "existing"})
			Expect(err).NotTo(HaveOccurred())

			group := &nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.GroupSpec{
					Name: "existing",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			err = k8sClient.Get(ctx, nn, group)
			Expect(err).NotTo(HaveOccurred())
			Expect(group.Status.GroupID).To(Equal(existing.Id))

			groups, err := controllerReconciler.Netbird.Groups.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			named := 0
			for _, g := range groups {
				if g.Name == "existing" {
					named++
				}
			}
			Expect(named).To(Equal(1))
		})

		It("does not adopt a Netbird group that another Group owns", func() {
			owner := &nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.GroupSpec{
					Name: "shared",
				},
			}
			Expect(k8sClient.Create(ctx, owner)).To(Succeed())
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, nn, owner)).To(Succeed())
			Expect(owner.Status.GroupID).NotTo(BeEmpty())

			otherKey := client.ObjectKey{Name: "other-resource", Namespace: nn.Namespace}
			other := &nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      otherKey.Name,
					Namespace: otherKey.Namespace,
				},
				Spec: nbv1alpha1.GroupSpec{
					Name: "shared",
				},
			}
			Expect(k8sClient.Create(ctx, other)).To(Succeed())
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: otherKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, otherKey, other)).To(Succeed())
			Expect(other.Status.GroupID).To(BeEmpty())
			ready := conditions.Get(other, nbv1alpha1.ReadyCondition)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(nbv1alpha1.ConflictReason))

			By("leaving the owner's group in place when the other Group is deleted")
			Expect(k8sClient.Delete(ctx, other)).To(Succeed())
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: otherKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = controllerReconciler.Netbird.Groups.Get(ctx, owner.Status.GroupID)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
