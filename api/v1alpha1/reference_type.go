// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

type CrossNamespaceReference struct {
	// Name of the referent.
	// +required
	Name string `json:"name"`

	// Namespace of the referent.
	// +required
	Namespace string `json:"namespace"`
}
