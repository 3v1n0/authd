package gdm

import (
	"encoding/hex"
	"fmt"
	"testing"
	"unsafe"

	"github.com/msteinert/pam"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/pam/pam_test"
	"github.com/ubuntu/authd/pam/utils"
)

func TestSendToGdm(t *testing.T) {
	// t.Parallel()
	t.Cleanup(utils.MaybeDoLeakCheck)

	testCases := map[string]struct {
		value          []byte
		expectedReturn []byte
		expectedError  error
	}{
		"empty data": {
			value: []byte{},
		},

		"null data": {
			value: nil,
		},

		"single-char": {
			value: []byte("m"),
		},

		"lorem ipsum string data": {
			value: []byte(`
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
	tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
	quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
	consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
	cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
	non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
`),
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			// t.Parallel()
			t.Cleanup(utils.MaybeDoLeakCheck)

			convFuncCalled := true
			mt := pam_test.NewModuleTransactionDummy(func() pam.BinaryConversationFunc {
				return pam.BinaryConversationFunc(
					func(ptr pam.BinaryPointer) ([]byte, error) {
						fmt.Println("Received Ptr", ptr)
						convFuncCalled = true
						require.NotNil(t, ptr)
						req, err := decodeStringProtoMessage(ptr)
						require.NoError(t, err)
						require.Equal(t, tc.value, req)
						if tc.expectedReturn != nil {
							return tc.expectedReturn,
								tc.expectedError
						}
						fmt.Println("Request was", len(req), "\n"+hex.Dump(req))
						msg := newStringProtoMessage(req)
						// ret := make([]byte, unsafe.Sizeof(*msg))
						// copy(ret, *(*[]byte)(unsafe.Pointer(&msg)))
						// ret := *(*[]byte)(unsafe.Pointer(&msg))
						ret := msg.toBytes()
						fmt.Println("Sending\n", hex.Dump(ret), "\nptr is", unsafe.Pointer(&ret))
						return ret, tc.expectedError
					})
			}())

			data, err := sendToGdm(mt, tc.value)
			require.True(t, convFuncCalled)

			if tc.expectedError != nil {
				require.Nil(t, data)
				require.Error(t, tc.expectedError, err)
				return
			}

			require.NoError(t, err)

			if tc.expectedReturn != nil {
				require.Equal(t, tc.expectedReturn, data)
			} else {
				require.Equal(t, tc.value, data)
			}
		})
	}
}
