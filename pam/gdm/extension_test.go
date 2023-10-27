package gdm

import (
	"slices"
	"testing"

	"github.com/msteinert/pam"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/pam/pam_test"
)

// Subtests can't be parallel as they act on global data
//
//nolint:tparallel
func TestGdmExtensionSupport(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	testCases := map[string]struct {
		advertisedExtensions []string
		checkExtensions      []string
		supportedExtensions  []string
	}{
		"Unknown extension is unsupported": {
			checkExtensions:     []string{"foo.extension"},
			supportedExtensions: nil,
		},

		"Extensions are advertised": {
			advertisedExtensions: []string{PamExtensionCustomJSON, "foo"},
			checkExtensions:      []string{PamExtensionCustomJSON, "foo"},
			supportedExtensions:  []string{PamExtensionCustomJSON, "foo"},
		},

		"The private string extension unsupported if not advertised": {
			checkExtensions:     []string{PamExtensionCustomJSON},
			supportedExtensions: nil,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// These tests can't be parallel since they act on env variables
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			AdvertisePamExtensions(tc.advertisedExtensions)
			t.Cleanup(func() { AdvertisePamExtensions(nil) })

			for _, ext := range tc.checkExtensions {
				require.Equal(t,
					slices.Contains(tc.supportedExtensions, ext),
					IsPamExtensionSupported(ext))
			}
		})
	}
}

func TestGdmJSONProto(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value []byte
	}{
		"With null data": {
			value: []byte("null"),
		},

		"With single int": {
			value: []byte("55"),
		},

		"With single float": {
			value: []byte("5.5"),
		},

		"With single string": {
			value: []byte(`"hello"`),
		},

		"With single boolean": {
			value: []byte("true"),
		},

		"With empty object": {
			value: []byte("{}"),
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			req, err := NewBinaryJSONProtoRequest(tc.value)
			require.NoError(t, err)
			t.Cleanup(req.Release)
			require.NotNil(t, req)
			require.NotNil(t, req.Pointer())
			require.Equal(t, pam.BinaryPrompt, req.Style())

			decoded, err := decodeJSONProtoMessage(req.Pointer())
			require.NoError(t, err)
			require.Equalf(t, tc.value, decoded, "JSON msimatch '%s' vs '%s'",
				string(tc.value), string(decoded))
		})
	}
}

func TestGdmJSONProtoRequestErrors(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value []byte
	}{
		"With empty data": {
			value: []byte{},
		},

		"With null data": {
			value: nil,
		},

		"With single char": {
			value: []byte("m"),
		},

		"With lorem ipsum string data": {
			value: []byte(`
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
	tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
	quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
	consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
	cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
	non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
`),
		},

		"With invalid JSON object": {
			value: []byte("{[,]}"),
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			req, err := NewBinaryJSONProtoRequest(tc.value)
			require.Nil(t, req)
			require.ErrorIs(t, err, ErrInvalidJSON)
		})
	}
}

func TestGdmJSONProtoResponseErrors(t *testing.T) {
	t.Parallel()
	t.Cleanup(pam_test.MaybeDoLeakCheck)

	testCases := map[string]struct {
		protoName    string
		protoVersion uint
		jsonValue    []byte

		wantError string
	}{
		"On proto name mismatch": {
			protoName:    "some.other.protocol",
			protoVersion: JSONProtoVersion,
			jsonValue:    []byte("nil"),
			wantError:    "protocol name or version mismatch",
		},

		"On proto version mismatch": {
			protoName:    JSONProtoName,
			protoVersion: JSONProtoVersion + 100,
			jsonValue:    []byte("nil"),
			wantError:    "protocol name or version mismatch",
		},

		"On nil JSON": {
			protoName:    JSONProtoName,
			protoVersion: JSONProtoVersion,
			jsonValue:    nil,
			wantError:    ErrInvalidJSON.Error(),
		},

		"On empty JSON": {
			protoName:    JSONProtoName,
			protoVersion: JSONProtoVersion,
			jsonValue:    []byte{},
			wantError:    ErrInvalidJSON.Error(),
		},

		"On invalid JSON": {
			protoName:    JSONProtoName,
			protoVersion: JSONProtoVersion,
			jsonValue:    []byte("{]"),
			wantError:    ErrInvalidJSON.Error(),
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(pam_test.MaybeDoLeakCheck)

			req := allocateJSONProtoMessage()
			t.Cleanup(req.release)
			req.init(tc.protoName, tc.protoVersion, tc.jsonValue)
			require.Equal(t, req.protoVersion(), tc.protoVersion)
			require.Equal(t, req.protoName(), tc.protoName)

			binReq := pam.NewBinaryConvRequest(req.encode(), nil)
			t.Cleanup(binReq.Release)

			require.NotNil(t, binReq)
			require.NotNil(t, binReq.Pointer())
			require.Equal(t, pam.BinaryPrompt, binReq.Style())

			decoded, err := decodeJSONProtoMessage(binReq.Pointer())
			require.Nil(t, decoded)
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}
