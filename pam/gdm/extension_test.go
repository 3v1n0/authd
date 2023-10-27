package gdm

import (
	"slices"
	"testing"

	"github.com/msteinert/pam"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/pam/utils"
)

// Subtests can't be parallel as they act on global data
//
//nolint:tparallel
func TestGdmExtensionSupport(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		advertisedExtensions []string
		checkExtensions      []string
		supportedExtensions  []string
	}{
		"unknown extension unsupported": {
			checkExtensions:     []string{"foo.extension"},
			supportedExtensions: nil,
		},

		"extensions advertised": {
			advertisedExtensions: []string{PamExtensionPrivateString, "foo"},
			checkExtensions:      []string{PamExtensionPrivateString, "foo"},
			supportedExtensions:  []string{PamExtensionPrivateString, "foo"},
		},

		"private string extension unsupported": {
			checkExtensions:     []string{PamExtensionPrivateString},
			supportedExtensions: nil,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// These tests can't be parallel since they act on env variables
			t.Cleanup(utils.MaybeDoLeakCheck)

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

func TestGdmStringProto(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value    string
		rawValue []byte
	}{
		"empty data": {
			rawValue: []byte{},
		},

		"null data": {
			rawValue: nil,
		},

		"single-char": {
			value: "m",
		},

		"lorem ipsum string data": {
			value: `
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
	tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
	quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
	consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
	cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
	non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
`,
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(utils.MaybeDoLeakCheck)

			var req *pam.BinaryConvRequest
			if tc.value != "" {
				req = NewBinaryStringProtoRequest([]byte(tc.value))
			} else {
				req = NewBinaryStringProtoRequest(tc.rawValue)
			}
			t.Cleanup(req.Release)
			require.NotNil(t, req)
			require.NotNil(t, req.Pointer())
			require.Equal(t, pam.BinaryPrompt, req.Style())

			decoded, err := decodeResponse(req.Pointer())
			require.NoError(t, err)
			if tc.value != "" {
				require.Equal(t, tc.value, string(decoded))
			} else {
				require.Equal(t, tc.rawValue, decoded)
			}
		})
	}
}

func TestGdmStringProtoErrors(t *testing.T) {
	t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		protoName    string
		protoVersion uint
	}{
		"proto name mismatch": {
			protoName:    "some.other.protocol",
			protoVersion: StringProtoVersion,
		},

		"proto version mismatch": {
			protoName:    StringProtoName,
			protoVersion: StringProtoVersion + 100,
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(utils.MaybeDoLeakCheck)

			req := newStringProtoMessage(nil)
			t.Cleanup(req.release)
			req.init(tc.protoName, tc.protoVersion, []byte("Some message data"))

			binReq := pam.NewBinaryConvRequest(req.encode(), nil)
			t.Cleanup(binReq.Release)

			require.NotNil(t, binReq)
			require.NotNil(t, binReq.Pointer())
			require.Equal(t, pam.BinaryPrompt, binReq.Style())

			decoded, err := decodeResponse(binReq.Pointer())
			require.ErrorContains(t, err, "protocol name or version mismatch")
			require.Nil(t, decoded)
		})
	}
}
