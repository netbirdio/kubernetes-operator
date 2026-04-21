package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

var _ = Describe("SetupKey Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var controllerReconciler *SetupKeyReconciler
		nn := client.ObjectKey{
			Name:      "test-resource",
			Namespace: "default",
		}

		BeforeEach(func() {
			controllerReconciler = &SetupKeyReconciler{
				Client:  k8sClient,
				Netbird: netbirdmock.Client(),
			}
		})

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
		})
	})
})
