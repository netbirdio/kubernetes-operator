package util

import "testing"

func TestEquivalentBy(t *testing.T) {
	type item struct {
		key   string
		value int
	}
	keyFn := func(i item) string { return i.key }

	tests := []struct {
		name string
		x    []item
		y    []item
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []item{}, []item{}, true},
		{"different lengths", []item{{key: "a"}}, []item{}, false},
		{"same elements", []item{{key: "a", value: 1}}, []item{{key: "a", value: 2}}, true},
		{"different keys", []item{{key: "a"}}, []item{{key: "b"}}, false},
		{
			"same keys different order",
			[]item{{key: "a"}, {key: "b"}},
			[]item{{key: "b"}, {key: "a"}},
			true,
		},
		{
			"duplicate keys in x only",
			[]item{{key: "a"}, {key: "a"}},
			[]item{{key: "a"}, {key: "b"}},
			false,
		},
		{
			"duplicate keys matched",
			[]item{{key: "a"}, {key: "a"}},
			[]item{{key: "a"}, {key: "a"}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EquivalentBy(tt.x, tt.y, keyFn); got != tt.want {
				t.Errorf("EquivalentBy() = %v, want %v", got, tt.want)
			}
		})
	}
}
