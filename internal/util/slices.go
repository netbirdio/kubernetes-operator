package util

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

// Equivalent return true if x and y are equal when sorted
func Equivalent[T comparable](x, y []T) bool {
	if len(x) != len(y) {
		return false
	}

	mp := make(map[T]interface{})
	for _, v := range x {
		mp[v] = nil
	}
	for _, v := range y {
		if _, ok := mp[v]; !ok {
			return false
		}
	}

	return true
}
