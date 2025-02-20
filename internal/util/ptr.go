package util

// Ptr return pointer to any value for API purposes
func Ptr[T any, PT *T](x T) PT {
	return &x
}

// Contains return if y is in slice x
func Contains[T comparable](x []T, y T) bool {
	for _, v := range x {
		if v == y {
			return true
		}
	}
	return false
}

// Without return all of x in same order without y
func Without[T comparable](x []T, y T) []T {
	var ret []T
	for _, v := range x {
		if v != y {
			ret = append(ret, v)
		}
	}
	return ret
}
