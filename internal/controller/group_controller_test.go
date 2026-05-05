// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
	})
})
