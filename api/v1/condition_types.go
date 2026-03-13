package v1

const (
	// ReadyCondition indicates that the resource is ready.
	ReadyCondition = "Ready"
)

const (
	// ResourceErrorReason is used for errors with Kubernetes resources.
	ResourceErrorReason = "ReasourceError"

	// APIErrorReason is used for errors related to the Netbird API.
	APIErrorReason = "APIError"

	// InvalidSpecReason is used for errors related to issues with given parameters.
	InvalidSpecReason = "InvalidSpec"
)
