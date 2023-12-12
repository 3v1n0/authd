//go:build !release

package gdm

import "encoding/json"

func validateJSON(jsonValue []byte) error {
	// FIXME: Disable this check in GDM builds, this is only useful
	// for testing as GDM does JSON sanity check by default.
	if !json.Valid(jsonValue) {
		return ErrInvalidJSON
	}
	return nil
}
