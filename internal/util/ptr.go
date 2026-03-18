package util

// Ptr return pointer to any value for API purposes
func Ptr[T any, PT *T](x T) PT {
	return &x
}

// PtrEqual compares two pointers by value, handling nil.
func PtrEqual[T comparable](a, b *T) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
