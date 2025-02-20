package util

// Ptr return pointer to any value for API purposes
func Ptr[T any, PT *T](x T) PT {
	return &x
}
