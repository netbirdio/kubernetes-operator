package k8sutil

const NetbirdFinalizer = "finalizers.netbird.io"

func Finalizer(kind string) string {
	return NetbirdFinalizer + "/" + kind
}
