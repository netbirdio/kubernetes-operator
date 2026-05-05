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

// Equivalent return true if x and y are equal when sorted
func Equivalent[T comparable](x, y []T) bool {
	if len(x) != len(y) {
		return false
	}

	mp := make(map[T]any)
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
