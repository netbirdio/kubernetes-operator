package util

import "testing"

func TestPtrEqual(t *testing.T) {
	a, b := "hello", "hello"
	c := "world"

	tests := []struct {
		name string
		a    *string
		b    *string
		want bool
	}{
		{"both nil", nil, nil, true},
		{"first nil", nil, &a, false},
		{"second nil", &a, nil, false},
		{"same pointer", &a, &a, true},
		{"equal values", &a, &b, true},
		{"different values", &a, &c, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PtrEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("PtrEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPtrEqual_Int(t *testing.T) {
	a, b := 42, 42
	c := 99

	tests := []struct {
		name string
		a    *int
		b    *int
		want bool
	}{
		{"both nil", nil, nil, true},
		{"first nil", nil, &a, false},
		{"equal values", &a, &b, true},
		{"different values", &a, &c, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PtrEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("PtrEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
