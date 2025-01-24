/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

var _ = Describe("NBSetupKey Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		nbsetupkey := &netbirdiov1.NBSetupKey{}
		secret := &v1.Secret{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind NBSetupKey")
			err := k8sClient.Get(ctx, typeNamespacedName, nbsetupkey)
			resource := &netbirdiov1.NBSetupKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: netbirdiov1.NBSetupKeySpec{
					SecretKeyRef: v1.SecretKeySelector{
						LocalObjectReference: v1.LocalObjectReference{
							Name: resourceName,
						},
						Key: "setupkey",
					},
				},
			}
			if err == nil {
				Expect(k8sClient.Delete(ctx, nbsetupkey)).To(Succeed())
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		})

		AfterEach(func() {
			resource := &netbirdiov1.NBSetupKey{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance NBSetupKey")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		When("No secret present", func() {
			It("should set status to not ready", func() {
				controllerReconciler := &NBSetupKeyReconciler{
					Client:            k8sClient,
					Scheme:            k8sClient.Scheme(),
					ReferencedSecrets: make(map[string]types.NamespacedName),
				}

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, typeNamespacedName, nbsetupkey)
				Expect(err).NotTo(HaveOccurred())

				Expect(nbsetupkey.Status.Conditions).NotTo(BeNil())
				Expect(nbsetupkey.Status.Conditions).To(HaveLen(1))
				Expect(nbsetupkey.Status.Conditions[0].Status).To(Equal(v1.ConditionFalse))
				Expect(nbsetupkey.Status.Conditions[0].Reason).To(Equal("SecretNotExists"))
				Expect(controllerReconciler.ReferencedSecrets).To(HaveKey("default/test-resource"))
			})
		})

		When("Secret present", Ordered, func() {
			createSecret := func(secretkey, setupkey string) {
				resource := &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
						Name:      resourceName,
					},
					Data: map[string][]byte{
						secretkey: []byte(setupkey),
					},
				}

				secret = &v1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: resourceName}, secret)
				if err == nil {
					Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}

			When("secret is invalid", func() {
				It("should set status to not ready", func() {
					createSecret("setupkey", "invalid-key")

					controllerReconciler := &NBSetupKeyReconciler{
						Client:            k8sClient,
						Scheme:            k8sClient.Scheme(),
						ReferencedSecrets: make(map[string]types.NamespacedName),
					}

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					err = k8sClient.Get(ctx, typeNamespacedName, nbsetupkey)
					Expect(err).NotTo(HaveOccurred())

					Expect(nbsetupkey.Status.Conditions).NotTo(BeNil())
					Expect(nbsetupkey.Status.Conditions).To(HaveLen(1))
					Expect(nbsetupkey.Status.Conditions[0].Status).To(Equal(v1.ConditionFalse))
					Expect(nbsetupkey.Status.Conditions[0].Reason).To(Equal("InvalidSetupKey"))
					Expect(controllerReconciler.ReferencedSecrets).To(HaveKey("default/test-resource"))
				})
			})

			When("secret key is missing", func() {
				It("should set status to not ready", func() {
					createSecret("key", "EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE")

					controllerReconciler := &NBSetupKeyReconciler{
						Client:            k8sClient,
						Scheme:            k8sClient.Scheme(),
						ReferencedSecrets: make(map[string]types.NamespacedName),
					}

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					err = k8sClient.Get(ctx, typeNamespacedName, nbsetupkey)
					Expect(err).NotTo(HaveOccurred())

					Expect(nbsetupkey.Status.Conditions).NotTo(BeNil())
					Expect(nbsetupkey.Status.Conditions).To(HaveLen(1))
					Expect(nbsetupkey.Status.Conditions[0].Status).To(Equal(v1.ConditionFalse))
					Expect(nbsetupkey.Status.Conditions[0].Reason).To(Equal("SecretKeyNotExists"))
					Expect(controllerReconciler.ReferencedSecrets).To(HaveKey("default/test-resource"))
				})
			})

			When("secret is valid", func() {
				It("should set status to ready", func() {
					createSecret("setupkey", "EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE")

					controllerReconciler := &NBSetupKeyReconciler{
						Client:            k8sClient,
						Scheme:            k8sClient.Scheme(),
						ReferencedSecrets: make(map[string]types.NamespacedName),
					}

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					err = k8sClient.Get(ctx, typeNamespacedName, nbsetupkey)
					Expect(err).NotTo(HaveOccurred())

					Expect(nbsetupkey.Status.Conditions).NotTo(BeNil())
					Expect(nbsetupkey.Status.Conditions).To(HaveLen(1))
					Expect(nbsetupkey.Status.Conditions[0].Status).To(Equal(v1.ConditionTrue))
					Expect(controllerReconciler.ReferencedSecrets).To(HaveKey("default/test-resource"))
				})
			})
		})
	})
})
