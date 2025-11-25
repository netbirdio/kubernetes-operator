package controller

import (
	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Service Controller", func() {
	Context("When reconciling a resource", func() {
		typeNamespacedName := types.NamespacedName{
			Namespace: "default",
			Name:      "test-resource",
		}
		const policyName = "test"
		var service *corev1.Service

		var controllerReconciler *ServiceReconciler

		BeforeEach(func() {
			service = &corev1.Service{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-resource",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:       "a",
							Protocol:   corev1.ProtocolTCP,
							Port:       80,
							TargetPort: intstr.FromInt(80),
						},
						{
							Name:       "b",
							Protocol:   corev1.ProtocolTCP,
							Port:       443,
							TargetPort: intstr.FromInt(443),
						},
						{
							Name:       "c",
							Protocol:   corev1.ProtocolUDP,
							Port:       80,
							TargetPort: intstr.FromInt(80),
						},
						{
							Name:       "d",
							Protocol:   corev1.ProtocolUDP,
							Port:       443,
							TargetPort: intstr.FromInt(443),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())
			controllerReconciler = &ServiceReconciler{
				Client:              k8sClient,
				Scheme:              k8sClient.Scheme(),
				ClusterName:         "kubernetes",
				NamespacedNetworks:  false,
				ClusterDNS:          "svc.cluster.local",
				ControllerNamespace: "default",
				DefaultLabels:       map[string]string{"dog": "bark"},
			}
		})

		AfterEach(func() {
			svc := &corev1.Service{}
			err := k8sClient.Get(ctx, typeNamespacedName, svc)
			if !errors.IsNotFound(err) {
				if len(svc.Finalizers) > 0 {
					svc.Finalizers = nil
					Expect(k8sClient.Update(ctx, svc)).To(Succeed())
				}

				err := k8sClient.Delete(ctx, svc)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}

			nbrp := &netbirdiov1.NBRoutingPeer{}
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "router"}, nbrp)
			if !errors.IsNotFound(err) {
				if len(nbrp.Finalizers) > 0 {
					nbrp.Finalizers = nil
					Expect(k8sClient.Update(ctx, nbrp)).To(Succeed())
				}

				err := k8sClient.Delete(ctx, nbrp)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}

			nbResource := &netbirdiov1.NBResource{}
			err = k8sClient.Get(ctx, typeNamespacedName, nbResource)
			if !errors.IsNotFound(err) {
				if len(nbResource.Finalizers) > 0 {
					nbResource.Finalizers = nil
					Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())
				}

				err := k8sClient.Delete(ctx, nbResource)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}
		})

		When("Service is not already exposed", func() {
			When("Service should not be exposed", func() {
				It("should change nothing", func() {
					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())
					Expect(k8sClient.Get(ctx, typeNamespacedName, service)).To(Succeed())
					Expect(service.Finalizers).To(BeEmpty())
					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).NotTo(Succeed())
				})
			})
			When("NBRoutingPeer doesn't exist", func() {
				BeforeEach(func() {
					if service.Annotations == nil {
						service.Annotations = make(map[string]string)
					}
					service.Annotations[ServiceExposeAnnotation] = "trueish"
					Expect(k8sClient.Update(ctx, service)).To(Succeed())
				})

				It("should create NBRoutingPeer and requeue until network ID is available", func() {
					res, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())
					Expect(res.RequeueAfter).NotTo(BeZero())
					nbrp := &netbirdiov1.NBRoutingPeer{}
					Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: typeNamespacedName.Namespace, Name: "router"}, nbrp)).To(Succeed())
					Expect(nbrp.Labels).To(HaveKeyWithValue("dog", "bark"))
					res, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())
					Expect(res.RequeueAfter).NotTo(BeZero())
					nbrp.Status.NetworkID = util.Ptr(policyName)
					Expect(k8sClient.Status().Update(ctx, nbrp)).To(Succeed())
					res, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())
					Expect(res.RequeueAfter).To(BeZero())
				})
			})
			When("NBRoutingPeer exists", func() {
				BeforeEach(func() {
					nbrp := &netbirdiov1.NBRoutingPeer{
						ObjectMeta: v1.ObjectMeta{
							Namespace: typeNamespacedName.Namespace,
							Name:      "router",
						},
						Spec: netbirdiov1.NBRoutingPeerSpec{},
					}
					Expect(k8sClient.Create(ctx, nbrp)).To(Succeed())

					nbrp.Status.NetworkID = util.Ptr(policyName)
					Expect(k8sClient.Status().Update(ctx, nbrp)).To(Succeed())
				})
				When("Service should be exposed", func() {
					BeforeEach(func() {
						if service.Annotations == nil {
							service.Annotations = make(map[string]string)
						}
						service.Annotations[ServiceExposeAnnotation] = "true"
						Expect(k8sClient.Update(ctx, service)).To(Succeed())
					})
					It("should add finalizer to service object", func() {
						_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
							NamespacedName: typeNamespacedName,
						})
						Expect(err).NotTo(HaveOccurred())
						Expect(k8sClient.Get(ctx, typeNamespacedName, service)).To(Succeed())
						Expect(service.Finalizers).To(ContainElement("netbird.io/cleanup"))
					})
					When("nothing else is specified", func() {
						It("should create NBResource with default values", func() {
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())
							nbResource := &netbirdiov1.NBResource{}
							Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
							Expect(nbResource.Spec.Address).To(Equal(typeNamespacedName.Name + "." + typeNamespacedName.Namespace + "." + controllerReconciler.ClusterDNS))
							Expect(nbResource.Spec.Groups).To(ConsistOf([]string{controllerReconciler.ClusterName + "-" + typeNamespacedName.Namespace + "-" + typeNamespacedName.Name}))
							Expect(nbResource.Spec.Name).To(Equal(typeNamespacedName.Namespace + "-" + typeNamespacedName.Name))
							Expect(nbResource.Spec.NetworkID).To(Equal(policyName))
							Expect(nbResource.Spec.PolicyName).To(BeEmpty())
							Expect(nbResource.Spec.TCPPorts).To(BeEmpty())
							Expect(nbResource.Spec.UDPPorts).To(BeEmpty())
							Expect(nbResource.Labels).To(HaveKeyWithValue("dog", "bark"))
						})
					})
					When("policy is specified", func() {
						BeforeEach(func() {
							service.Annotations[servicePolicyAnnotation] = policyName
							Expect(k8sClient.Update(ctx, service)).To(Succeed())
						})
						When("nothing is restricted", func() {
							It("should create NBResource with policy", func() {
								_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								nbResource := &netbirdiov1.NBResource{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
								Expect(nbResource.Spec.PolicyName).To(Equal(policyName))
								Expect(nbResource.Spec.TCPPorts).To(ConsistOf([]int32{443, 80}))
								Expect(nbResource.Spec.UDPPorts).To(ConsistOf([]int32{443, 80}))
							})
						})
						When("ports are restricted", func() {
							It("should create NBResource with policy and only specified ports", func() {
								service.Annotations[servicePortsAnnotation] = "80"
								Expect(k8sClient.Update(ctx, service)).To(Succeed())

								_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								nbResource := &netbirdiov1.NBResource{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
								Expect(nbResource.Spec.PolicyName).To(Equal(policyName))
								Expect(nbResource.Spec.TCPPorts).To(ConsistOf([]int32{80}))
								Expect(nbResource.Spec.UDPPorts).To(ConsistOf([]int32{80}))
							})
						})
						When("protocol is restricted", func() {
							It("should create NBResource with policy and only specified protocol", func() {
								service.Annotations[serviceProtocolAnnotation] = "tcp"
								Expect(k8sClient.Update(ctx, service)).To(Succeed())

								_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
									NamespacedName: typeNamespacedName,
								})
								Expect(err).NotTo(HaveOccurred())
								nbResource := &netbirdiov1.NBResource{}
								Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
								Expect(nbResource.Spec.PolicyName).To(Equal(policyName))
								Expect(nbResource.Spec.TCPPorts).To(ConsistOf([]int32{80, 443}))
								Expect(nbResource.Spec.UDPPorts).To(BeEmpty())
							})
						})
					})
					When("resource name is specified", func() {
						It("should create NBResource with specified name", func() {
							service.Annotations[serviceResourceAnnotation] = "meow"
							Expect(k8sClient.Update(ctx, service)).To(Succeed())
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())
							nbResource := &netbirdiov1.NBResource{}
							Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
							Expect(nbResource.Spec.Name).To(Equal("meow"))
						})
					})
					When("resource groups specified", func() {
						It("should create NBResource with specified groups", func() {
							service.Annotations[serviceGroupsAnnotation] = "meow, wow ,test"
							Expect(k8sClient.Update(ctx, service)).To(Succeed())
							_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
								NamespacedName: typeNamespacedName,
							})
							Expect(err).NotTo(HaveOccurred())
							nbResource := &netbirdiov1.NBResource{}
							Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
							Expect(nbResource.Spec.Groups).To(ConsistOf([]string{"meow", "wow", policyName}))
						})
					})
				})
			})
		})
		When("Service is already exposed", func() {
			BeforeEach(func() {
				nbResource := &netbirdiov1.NBResource{
					ObjectMeta: v1.ObjectMeta{
						Name:      typeNamespacedName.Name,
						Namespace: typeNamespacedName.Namespace,
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:      typeNamespacedName.Namespace + "-" + typeNamespacedName.Name,
						Address:   typeNamespacedName.Name + "." + typeNamespacedName.Namespace + "." + controllerReconciler.ClusterDNS,
						Groups:    []string{controllerReconciler.ClusterName + "-" + typeNamespacedName.Namespace + "-" + typeNamespacedName.Name},
						NetworkID: policyName,
					},
				}
				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				if service.Annotations == nil {
					service.Annotations = make(map[string]string)
				}
				service.Annotations[ServiceExposeAnnotation] = "true"
				Expect(k8sClient.Update(ctx, service)).To(Succeed())

				nbrp := &netbirdiov1.NBRoutingPeer{
					ObjectMeta: v1.ObjectMeta{
						Namespace: typeNamespacedName.Namespace,
						Name:      "router",
					},
					Spec: netbirdiov1.NBRoutingPeerSpec{},
				}
				Expect(k8sClient.Create(ctx, nbrp)).To(Succeed())

				nbrp.Status.NetworkID = util.Ptr(policyName)
				Expect(k8sClient.Status().Update(ctx, nbrp)).To(Succeed())
			})

			When("Service should not be exposed", func() {
				BeforeEach(func() {
					delete(service.Annotations, ServiceExposeAnnotation)
					Expect(k8sClient.Update(ctx, service)).To(Succeed())
				})
				It("should delete NBResource", func() {
					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())
					nbResource := &netbirdiov1.NBResource{}
					err = k8sClient.Get(ctx, typeNamespacedName, nbResource)
					if !errors.IsNotFound(err) {
						Expect(nbResource.DeletionTimestamp).NotTo(BeNil())
					}
				})
				It("should remove finalizer from Service", func() {
					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())
					Expect(k8sClient.Get(ctx, typeNamespacedName, service)).To(Succeed())
					Expect(service.Finalizers).NotTo(ContainElement("netbird.io/cleanup"))
				})
			})
			When("Nothing changes", func() {
				It("should do nothing", func() {
					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					resourceVersion := nbResource.ResourceVersion

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource = &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(resourceVersion).To(BeEquivalentTo(nbResource.ResourceVersion))
				})
			})
			When("policy changes", func() {
				It("should update policy in NBResource spec", func() {
					service.Annotations[servicePolicyAnnotation] = policyName
					Expect(k8sClient.Update(ctx, service)).To(Succeed())
					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(nbResource.Spec.PolicyName).To(Equal(policyName))
				})
			})
			When("policy is removed", func() {
				It("should remove policy in NBResource spec", func() {
					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					nbResource.Spec.PolicyName = policyName
					Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource = &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(nbResource.Spec.PolicyName).To(Equal(""))
				})
			})
			When("policy ports changes", func() {
				It("should update ports in NBResource spec", func() {
					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					nbResource.Spec.PolicyName = policyName
					nbResource.Spec.TCPPorts = []int32{443, 80}
					nbResource.Spec.UDPPorts = []int32{443, 80}
					Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())

					service.Annotations[servicePolicyAnnotation] = policyName
					service.Annotations[servicePortsAnnotation] = "80"
					Expect(k8sClient.Update(ctx, service)).To(Succeed())

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource = &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(nbResource.Spec.TCPPorts).To(ConsistOf([]int32{80}))
					Expect(nbResource.Spec.UDPPorts).To(ConsistOf([]int32{80}))
				})
			})
			When("policy protocol changes", func() {
				It("should update protocol in NBResource spec", func() {
					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					nbResource.Spec.PolicyName = policyName
					nbResource.Spec.TCPPorts = []int32{443, 80}
					nbResource.Spec.UDPPorts = []int32{443, 80}
					Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())

					service.Annotations[servicePolicyAnnotation] = policyName
					service.Annotations[serviceProtocolAnnotation] = "tcp"
					Expect(k8sClient.Update(ctx, service)).To(Succeed())

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource = &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(nbResource.Spec.TCPPorts).To(ConsistOf([]int32{80, 443}))
					Expect(nbResource.Spec.UDPPorts).To(BeEmpty())
				})
			})
			When("policy friendly name changes", func() {
				It("should update policy friendly name in NBResource spec", func() {
					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					nbResource.Spec.PolicyName = policyName
					Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())

					service.Annotations[servicePolicyAnnotation] = policyName
					service.Annotations[servicePolicyNameAnnotation] = "test:toast,meow:meow"
					Expect(k8sClient.Update(ctx, service)).To(Succeed())

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource = &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(nbResource.Spec.PolicyFriendlyName).To(BeEquivalentTo(map[string]string{"test": "toast", "meow": "meow"}))
				})
			})
			When("policy source groups changes", func() {
				It("should update policy source groups in NBResource spec", func() {
					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					nbResource.Spec.PolicyName = policyName
					Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())

					service.Annotations[servicePolicyAnnotation] = policyName
					service.Annotations[servicePolicySourceGroupsAnnotation] = "test"
					Expect(k8sClient.Update(ctx, service)).To(Succeed())

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource = &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(nbResource.Spec.PolicySourceGroups).To(BeEquivalentTo([]string{"test"}))
				})
			})
			When("resource name changes", func() {
				It("should update name in NBResource spec", func() {
					service.Annotations[serviceResourceAnnotation] = "meow"
					Expect(k8sClient.Update(ctx, service)).To(Succeed())
					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(nbResource.Spec.Name).To(Equal("meow"))
				})
			})
			When("resource groups changes", func() {
				It("should update groups in NBResource spec", func() {
					service.Annotations[serviceGroupsAnnotation] = "a7medmo7sen, pewpewpew"
					Expect(k8sClient.Update(ctx, service)).To(Succeed())
					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())

					nbResource := &netbirdiov1.NBResource{}
					Expect(k8sClient.Get(ctx, typeNamespacedName, nbResource)).To(Succeed())
					Expect(nbResource.Spec.Groups).To(ConsistOf([]string{"a7medmo7sen", "pewpewpew"}))
				})
			})
		})
	})
})
