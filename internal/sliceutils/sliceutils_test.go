package sliceutils_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/internal/sliceutils"
)

func TestDifference(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		a, b, want []int
	}{
		"test_difference_between_two_slices": {
			a:    []int{1, 2, 3, 4, 5},
			b:    []int{3, 4, 5, 6, 7},
			want: []int{1, 2},
		},
		"test_difference_between_an_empty_slice_and_a_non-empty_slice": {
			a:    []int{},
			b:    []int{3, 4, 5, 6, 7},
			want: []int(nil),
		},
		"test_difference_between_a_non-empty_slice_and_an_empty_slice": {
			a:    []int{1, 2, 3, 4, 5},
			b:    []int{},
			want: []int{1, 2, 3, 4, 5},
		},
		"test_difference_between_two_empty_slices": {
			a:    []int{},
			b:    []int{},
			want: []int(nil),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := sliceutils.Difference(tc.a, tc.b)
			require.Equal(t, tc.want, got)
		})
	}
}

type notComparable struct {
	i  int
	ii []int
}

func notComparableCompareFunc(a notComparable, b notComparable) bool {
	return a.i == b.i && slices.Equal(a.ii, b.ii)
}

func TestDifferenceFunc(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		a, b, want []notComparable
	}{
		"test_difference_between_two_slices": {
			a:    []notComparable{{i: 1}, {i: 2}, {i: 3}, {i: 4}, {i: 5, ii: []int{1, 2}}},
			b:    []notComparable{{i: 3}, {i: 4}, {i: 5}, {i: 6}, {i: 7}},
			want: []notComparable{{i: 1}, {i: 2}, {i: 5, ii: []int{1, 2}}},
		},
		"test_difference_between_an_empty_slice_and_a_non-empty_slice": {
			a:    []notComparable{},
			b:    []notComparable{{i: 3}, {i: 4}, {i: 5}, {i: 6}, {i: 7}},
			want: []notComparable(nil),
		},
		"test_difference_between_a_non-empty_slice_and_an_empty_slice": {
			a:    []notComparable{{i: 1}, {i: 2}, {i: 3}, {i: 4}, {i: 5}},
			b:    []notComparable{},
			want: []notComparable{{i: 1}, {i: 2}, {i: 3}, {i: 4}, {i: 5}},
		},
		"test_difference_between_two_empty_slices": {
			a:    []notComparable{},
			b:    []notComparable{},
			want: []notComparable(nil),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := sliceutils.DifferenceFunc(tc.a, tc.b, notComparableCompareFunc)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestIntersection(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		a, b, want []int
	}{
		"test_intersection_between_two_slices": {
			a:    []int{1, 2, 3, 4, 5},
			b:    []int{3, 4, 5, 6, 7},
			want: []int{3, 4, 5},
		},
		"test_intersection_between_an_empty_slice_and_a_non-empty_slice": {
			a:    []int{},
			b:    []int{3, 4, 5, 6, 7},
			want: []int(nil),
		},
		"test_intersection_between_a_non-empty_slice_and_an_empty_slice": {
			a:    []int{1, 2, 3, 4, 5},
			b:    []int{},
			want: []int(nil),
		},
		"test_intersection_between_two_empty_slices": {
			a:    []int{},
			b:    []int{},
			want: []int(nil),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := sliceutils.Intersection(tc.a, tc.b)
			require.Equal(t, tc.want, got)
		})
	}
}
func TestIntersectionFunc(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		a, b, want []notComparable
	}{
		"test_intersection_between_two_slices": {
			a:    []notComparable{{i: 1}, {i: 2}, {i: 3}, {i: 4}, {i: 5}, {i: 6, ii: []int{7, 8}}, {i: 8, ii: []int{9}}},
			b:    []notComparable{{i: 3}, {i: 4}, {i: 5}, {i: 6}, {i: 7}, {i: 6, ii: []int{7, 8}}, {i: 8}},
			want: []notComparable{{i: 3}, {i: 4}, {i: 5}, {i: 6, ii: []int{7, 8}}},
		},
		"test_intersection_between_an_empty_slice_and_a_non-empty_slice": {
			a:    []notComparable{},
			b:    []notComparable{{i: 3}, {i: 4}, {i: 5}, {i: 6}, {i: 7}},
			want: []notComparable(nil),
		},
		"test_intersection_between_a_non-empty_slice_and_an_empty_slice": {
			a:    []notComparable{{i: 1}, {i: 2}, {i: 3}, {i: 4}, {i: 5}},
			b:    []notComparable{},
			want: []notComparable(nil),
		},
		"test_intersection_between_two_empty_slices": {
			a:    []notComparable{},
			b:    []notComparable{},
			want: []notComparable(nil),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := sliceutils.IntersectionFunc(tc.a, tc.b, notComparableCompareFunc)
			require.Equal(t, tc.want, got)
		})
	}
}
