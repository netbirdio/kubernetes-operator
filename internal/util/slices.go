// SPDX-License-Identifier: BSD-3-Clause

package util

import "strings"

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

// Equivalent returns true if x and y contain the same elements with the same
// multiplicity, regardless of order.
func Equivalent[T comparable](x, y []T) bool {
	if len(x) != len(y) {
		return false
	}

	counts := make(map[T]int, len(x))
	for _, v := range x {
		counts[v]++
	}
	for _, v := range y {
		if counts[v] == 0 {
			return false
		}
		counts[v]--
	}

	return true
}

// PtrEqual returns true if both pointers are nil or point to equal values.
func PtrEqual[T comparable](x, y *T) bool {
	if x == nil || y == nil {
		return x == y
	}
	return *x == *y
}

// SplitTrim split string and trim whitespace
func SplitTrim(str, sep string) []string {
	if len(str) == 0 {
		return nil
	}
	sp := strings.Split(str, sep)
	ret := make([]string, 0, len(sp))
	for _, v := range sp {
		ret = append(ret, strings.TrimSpace(v))
	}
	return ret
}
