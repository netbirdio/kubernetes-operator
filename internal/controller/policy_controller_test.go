// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

var _ = Describe("Policy Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		var policyRec *PolicyReconciler
		var nbRecorder *netbirdmock.Recorder
		var nn client.ObjectKey
		var sourceID, destinationID string

		BeforeEach(func() {
			var nbClient *netbird.Client
			nbClient, nbRecorder = netbirdmock.RecordingClient()
			policyRec = &PolicyReconciler{
				Client:  k8sClient,
				Netbird: nbClient,
			}

			source, err := policyRec.Netbird.Groups.Create(ctx, api.GroupRequest{Name: "developers"})
			Expect(err).NotTo(HaveOccurred())
			sourceID = source.Id
			destination, err := policyRec.Netbird.Groups.Create(ctx, api.GroupRequest{Name: "services"})
			Expect(err).NotTo(HaveOccurred())
			destinationID = destination.Id

			// Envtest never finishes deleting a namespace, so every spec gets its own.
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "policy-",
				},
			}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())
			nn = client.ObjectKey{
				Name:      "test-resource",
				Namespace: ns.Name,
			}
		})

		newPolicy := func() *nbv1alpha1.Policy {
			return &nbv1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.PolicySpec{
					Name:              "developers-to-services",
					SourceGroups:      []nbv1alpha1.GroupReference{{Name: new("developers")}},
					DestinationGroups: []nbv1alpha1.GroupReference{{ID: new(destinationID)}},
					Protocol:          "tcp",
					Ports:             []int32{443},
					PortRanges:        []nbv1alpha1.PortRange{{Start: 8000, End: 8080}},
				},
			}
		}

		reconcilePolicy := func(policy *nbv1alpha1.Policy) {
			_, err := policyRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, nn, policy)).To(Succeed())
		}

		It("creates a policy with one rule between the groups", func() {
			policy := newPolicy()
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			reconcilePolicy(policy)

			Expect(meta.IsStatusConditionTrue(policy.Status.Conditions, nbv1alpha1.ReadyCondition)).To(BeTrue())
			Expect(policy.Status.ObservedGeneration).To(Equal(policy.Generation))
			resp, err := policyRec.Netbird.Policies.Get(ctx, policy.Status.PolicyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Name).To(Equal("developers-to-services"))
			Expect(resp.Enabled).To(BeTrue())
			Expect(resp.Rules).To(HaveLen(1))
			rule := resp.Rules[0]
			Expect(rule.Action).To(Equal(api.PolicyRuleActionAccept))
			Expect(rule.Protocol).To(Equal(api.PolicyRuleProtocolTcp))
			Expect(*rule.Ports).To(Equal([]string{"443"}))
			Expect(*rule.PortRanges).To(Equal([]api.RulePortRange{{Start: 8000, End: 8080}}))
			Expect(*rule.Sources).To(Equal([]api.GroupMinimum{{Id: sourceID}}))
			Expect(*rule.Destinations).To(Equal([]api.GroupMinimum{{Id: destinationID}}))
		})

		It("updates the policy only when it differs from the spec", func() {
			policy := newPolicy()
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			reconcilePolicy(policy)

			By("leaving a policy that already matches untouched")
			reconcilePolicy(policy)
			reconcilePolicy(policy)
			Expect(nbRecorder.Count("PUT /api/policies/{id}")).To(Equal(0))

			By("reverting a change made outside the cluster")
			resp, err := policyRec.Netbird.Policies.Get(ctx, policy.Status.PolicyID)
			Expect(err).NotTo(HaveOccurred())
			_, err = policyRec.Netbird.Policies.Update(ctx, policy.Status.PolicyID, api.PolicyCreate{
				Name:    resp.Name,
				Enabled: false,
				Rules:   []api.PolicyRuleUpdate{},
			})
			Expect(err).NotTo(HaveOccurred())
			reconcilePolicy(policy)
			Expect(nbRecorder.Count("PUT /api/policies/{id}")).To(Equal(2))
			resp, err = policyRec.Netbird.Policies.Get(ctx, policy.Status.PolicyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Enabled).To(BeTrue())
			Expect(resp.Rules).To(HaveLen(1))

			By("applying a change of the spec")
			policy.Spec.Protocol = "all"
			policy.Spec.Ports = nil
			policy.Spec.PortRanges = nil
			Expect(k8sClient.Update(ctx, policy)).To(Succeed())
			reconcilePolicy(policy)
			resp, err = policyRec.Netbird.Policies.Get(ctx, policy.Status.PolicyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Rules[0].Protocol).To(Equal(api.PolicyRuleProtocolAll))
			Expect(resp.Rules[0].Ports).To(BeNil())
		})

		It("recreates a policy deleted outside the cluster", func() {
			policy := newPolicy()
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			reconcilePolicy(policy)
			oldID := policy.Status.PolicyID

			Expect(policyRec.Netbird.Policies.Delete(ctx, oldID)).To(Succeed())
			reconcilePolicy(policy)
			Expect(policy.Status.PolicyID).NotTo(Equal(oldID))
			_, err := policyRec.Netbird.Policies.Get(ctx, policy.Status.PolicyID)
			Expect(err).NotTo(HaveOccurred())
		})

		It("deletes the policy with the resource", func() {
			policy := newPolicy()
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			reconcilePolicy(policy)
			policyID := policy.Status.PolicyID

			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			_, err := policyRec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			Expect(kerrors.IsNotFound(k8sClient.Get(ctx, nn, policy))).To(BeTrue())
			_, err = policyRec.Netbird.Policies.Get(ctx, policyID)
			Expect(netbird.IsNotFound(err)).To(BeTrue())
		})

		It("rejects ports without protocol tcp or udp", func() {
			policy := newPolicy()
			policy.Spec.Protocol = "all"
			Expect(k8sClient.Create(ctx, policy)).NotTo(Succeed())

			policy = newPolicy()
			policy.Spec.PortRanges = []nbv1alpha1.PortRange{{Start: 9000, End: 8000}}
			Expect(k8sClient.Create(ctx, policy)).NotTo(Succeed())
		})
	})
})
