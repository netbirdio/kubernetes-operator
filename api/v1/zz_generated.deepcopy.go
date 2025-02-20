//go:build !ignore_autogenerated

// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
	corev1 "k8s.io/api/core/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBCondition) DeepCopyInto(out *NBCondition) {
	*out = *in
	in.LastProbeTime.DeepCopyInto(&out.LastProbeTime)
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBCondition.
func (in *NBCondition) DeepCopy() *NBCondition {
	if in == nil {
		return nil
	}
	out := new(NBCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBGroup) DeepCopyInto(out *NBGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBGroup.
func (in *NBGroup) DeepCopy() *NBGroup {
	if in == nil {
		return nil
	}
	out := new(NBGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBGroupList) DeepCopyInto(out *NBGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NBGroup, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBGroupList.
func (in *NBGroupList) DeepCopy() *NBGroupList {
	if in == nil {
		return nil
	}
	out := new(NBGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBGroupSpec) DeepCopyInto(out *NBGroupSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBGroupSpec.
func (in *NBGroupSpec) DeepCopy() *NBGroupSpec {
	if in == nil {
		return nil
	}
	out := new(NBGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBGroupStatus) DeepCopyInto(out *NBGroupStatus) {
	*out = *in
	if in.GroupID != nil {
		in, out := &in.GroupID, &out.GroupID
		*out = new(string)
		**out = **in
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]NBCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBGroupStatus.
func (in *NBGroupStatus) DeepCopy() *NBGroupStatus {
	if in == nil {
		return nil
	}
	out := new(NBGroupStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBPolicy) DeepCopyInto(out *NBPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBPolicy.
func (in *NBPolicy) DeepCopy() *NBPolicy {
	if in == nil {
		return nil
	}
	out := new(NBPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBPolicyList) DeepCopyInto(out *NBPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NBPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBPolicyList.
func (in *NBPolicyList) DeepCopy() *NBPolicyList {
	if in == nil {
		return nil
	}
	out := new(NBPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBPolicySpec) DeepCopyInto(out *NBPolicySpec) {
	*out = *in
	if in.SourceGroups != nil {
		in, out := &in.SourceGroups, &out.SourceGroups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DestinationGroups != nil {
		in, out := &in.DestinationGroups, &out.DestinationGroups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Protocols != nil {
		in, out := &in.Protocols, &out.Protocols
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make([]int32, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBPolicySpec.
func (in *NBPolicySpec) DeepCopy() *NBPolicySpec {
	if in == nil {
		return nil
	}
	out := new(NBPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBPolicyStatus) DeepCopyInto(out *NBPolicyStatus) {
	*out = *in
	if in.TCPPolicyID != nil {
		in, out := &in.TCPPolicyID, &out.TCPPolicyID
		*out = new(string)
		**out = **in
	}
	if in.UDPPolicyID != nil {
		in, out := &in.UDPPolicyID, &out.UDPPolicyID
		*out = new(string)
		**out = **in
	}
	if in.LastUpdatedAt != nil {
		in, out := &in.LastUpdatedAt, &out.LastUpdatedAt
		*out = (*in).DeepCopy()
	}
	if in.ManagedServiceList != nil {
		in, out := &in.ManagedServiceList, &out.ManagedServiceList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]NBCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBPolicyStatus.
func (in *NBPolicyStatus) DeepCopy() *NBPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(NBPolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBResource) DeepCopyInto(out *NBResource) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBResource.
func (in *NBResource) DeepCopy() *NBResource {
	if in == nil {
		return nil
	}
	out := new(NBResource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBResource) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBResourceList) DeepCopyInto(out *NBResourceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NBResource, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBResourceList.
func (in *NBResourceList) DeepCopy() *NBResourceList {
	if in == nil {
		return nil
	}
	out := new(NBResourceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBResourceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBResourceSpec) DeepCopyInto(out *NBResourceSpec) {
	*out = *in
	if in.Groups != nil {
		in, out := &in.Groups, &out.Groups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TCPPorts != nil {
		in, out := &in.TCPPorts, &out.TCPPorts
		*out = make([]int32, len(*in))
		copy(*out, *in)
	}
	if in.UDPPorts != nil {
		in, out := &in.UDPPorts, &out.UDPPorts
		*out = make([]int32, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBResourceSpec.
func (in *NBResourceSpec) DeepCopy() *NBResourceSpec {
	if in == nil {
		return nil
	}
	out := new(NBResourceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBResourceStatus) DeepCopyInto(out *NBResourceStatus) {
	*out = *in
	if in.NetworkResourceID != nil {
		in, out := &in.NetworkResourceID, &out.NetworkResourceID
		*out = new(string)
		**out = **in
	}
	if in.PolicyName != nil {
		in, out := &in.PolicyName, &out.PolicyName
		*out = new(string)
		**out = **in
	}
	if in.TCPPorts != nil {
		in, out := &in.TCPPorts, &out.TCPPorts
		*out = make([]int32, len(*in))
		copy(*out, *in)
	}
	if in.UDPPorts != nil {
		in, out := &in.UDPPorts, &out.UDPPorts
		*out = make([]int32, len(*in))
		copy(*out, *in)
	}
	if in.Groups != nil {
		in, out := &in.Groups, &out.Groups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]NBCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBResourceStatus.
func (in *NBResourceStatus) DeepCopy() *NBResourceStatus {
	if in == nil {
		return nil
	}
	out := new(NBResourceStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBRoutingPeer) DeepCopyInto(out *NBRoutingPeer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBRoutingPeer.
func (in *NBRoutingPeer) DeepCopy() *NBRoutingPeer {
	if in == nil {
		return nil
	}
	out := new(NBRoutingPeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBRoutingPeer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBRoutingPeerList) DeepCopyInto(out *NBRoutingPeerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NBRoutingPeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBRoutingPeerList.
func (in *NBRoutingPeerList) DeepCopy() *NBRoutingPeerList {
	if in == nil {
		return nil
	}
	out := new(NBRoutingPeerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBRoutingPeerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBRoutingPeerSpec) DeepCopyInto(out *NBRoutingPeerSpec) {
	*out = *in
	if in.Replicas != nil {
		in, out := &in.Replicas, &out.Replicas
		*out = new(int32)
		**out = **in
	}
	in.Resources.DeepCopyInto(&out.Resources)
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Tolerations != nil {
		in, out := &in.Tolerations, &out.Tolerations
		*out = make([]corev1.Toleration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBRoutingPeerSpec.
func (in *NBRoutingPeerSpec) DeepCopy() *NBRoutingPeerSpec {
	if in == nil {
		return nil
	}
	out := new(NBRoutingPeerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBRoutingPeerStatus) DeepCopyInto(out *NBRoutingPeerStatus) {
	*out = *in
	if in.NetworkID != nil {
		in, out := &in.NetworkID, &out.NetworkID
		*out = new(string)
		**out = **in
	}
	if in.SetupKeyID != nil {
		in, out := &in.SetupKeyID, &out.SetupKeyID
		*out = new(string)
		**out = **in
	}
	if in.RouterID != nil {
		in, out := &in.RouterID, &out.RouterID
		*out = new(string)
		**out = **in
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]NBCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBRoutingPeerStatus.
func (in *NBRoutingPeerStatus) DeepCopy() *NBRoutingPeerStatus {
	if in == nil {
		return nil
	}
	out := new(NBRoutingPeerStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBSetupKey) DeepCopyInto(out *NBSetupKey) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBSetupKey.
func (in *NBSetupKey) DeepCopy() *NBSetupKey {
	if in == nil {
		return nil
	}
	out := new(NBSetupKey)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBSetupKey) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBSetupKeyList) DeepCopyInto(out *NBSetupKeyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NBSetupKey, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBSetupKeyList.
func (in *NBSetupKeyList) DeepCopy() *NBSetupKeyList {
	if in == nil {
		return nil
	}
	out := new(NBSetupKeyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NBSetupKeyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBSetupKeySpec) DeepCopyInto(out *NBSetupKeySpec) {
	*out = *in
	in.SecretKeyRef.DeepCopyInto(&out.SecretKeyRef)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBSetupKeySpec.
func (in *NBSetupKeySpec) DeepCopy() *NBSetupKeySpec {
	if in == nil {
		return nil
	}
	out := new(NBSetupKeySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NBSetupKeyStatus) DeepCopyInto(out *NBSetupKeyStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]NBCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NBSetupKeyStatus.
func (in *NBSetupKeyStatus) DeepCopy() *NBSetupKeyStatus {
	if in == nil {
		return nil
	}
	out := new(NBSetupKeyStatus)
	in.DeepCopyInto(out)
	return out
}
