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

package v1

import (
	"context"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Pod Webhook", func() {
	var (
		obj       *corev1.Pod
		defaulter PodNetbirdInjector
	)

	BeforeEach(func() {
		obj = &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Name:        "test",
				Namespace:   "test",
				Annotations: make(map[string]string),
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "test",
					},
				},
			},
		}
		defaulter = PodNetbirdInjector{
			client:        k8sClient,
			managementURL: "https://api.netbird.io",
			clientImage:   "netbirdio/netbird:latest",
		}
		Expect(defaulter).NotTo(BeNil(), "Expected defaulter to be initialized")
		Expect(obj).NotTo(BeNil(), "Expected obj to be initialized")
	})

	AfterEach(func() {
	})

	Context("When creating Pod without annotation", func() {
		It("Should not modify anything", func() {
			err := defaulter.Default(context.Background(), obj)
			Expect(err).NotTo(HaveOccurred())
			Expect(obj.Spec.Containers).To(HaveLen(1))
		})
	})

	Context("When creating Pod with annotation", func() {
		BeforeEach(func() {
			obj.Annotations[setupKeyAnnotation] = "test"
		})

		When("NBSetupKey doesn't exist", func() {
			It("Should fail", func() {
				Expect(defaulter.Default(context.Background(), obj)).To(HaveOccurred())
				Expect(obj.Spec.Containers).To(HaveLen(1))
			})
		})

		When("NBSetupKey exists", Ordered, func() {
			BeforeAll(func() {
				sk := netbirdiov1.NBSetupKey{
					ObjectMeta: v1.ObjectMeta{
						Name:      "test",
						Namespace: "test",
					},
					Spec: netbirdiov1.NBSetupKeySpec{
						SecretKeyRef: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "test",
							},
							Key: "test",
						},
					},
				}

				err := k8sClient.Create(context.Background(), &corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{
						Name: "test",
					},
				})
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Create(context.Background(), &sk)
				Expect(err).NotTo(HaveOccurred())

				sk.Status = netbirdiov1.NBSetupKeyStatus{
					Conditions: []netbirdiov1.NBCondition{
						{
							Type:   netbirdiov1.NBSetupKeyReady,
							Status: corev1.ConditionTrue,
						},
					},
				}

				err = k8sClient.Status().Update(context.Background(), &sk)
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should inject NB container", func() {
				Expect(defaulter.Default(context.Background(), obj)).NotTo(HaveOccurred())
				Expect(obj.Spec.Containers).To(HaveLen(2))
				Expect(obj.Spec.Containers[1].Name).To(Equal("netbird"))
			})
		})
	})
})
