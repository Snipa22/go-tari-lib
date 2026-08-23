// Copyright and license: see repository LICENSE (MIT).
package address

import "errors"

// TariAddressError values mirror, one-for-one, the variants of Rust's
// tari_common_types::tari_address::TariAddressError enum
// (tari_address/mod.rs). Callers that need to distinguish a specific
// failure mode can compare with errors.Is against these sentinels.
var (
	ErrInvalidSize            = errors.New("address: invalid size")
	ErrInvalidNetwork         = errors.New("address: invalid network")
	ErrInvalidFeatures        = errors.New("address: invalid features")
	ErrInvalidChecksum        = errors.New("address: invalid checksum")
	ErrInvalidEmoji           = errors.New("address: invalid emoji character")
	ErrInvalidCharacter       = errors.New("address: invalid text character")
	ErrCannotRecoverPublicKey = errors.New("address: cannot recover public key")
	ErrCannotRecoverNetwork   = errors.New("address: cannot recover network")
	ErrCannotRecoverFeature   = errors.New("address: cannot recover feature")
	ErrInvalidAddressString   = errors.New("address: could not recover TariAddress from string")
	ErrPaymentIDTooLarge      = errors.New("address: too large payment_id")
	ErrPaymentIDNotSupported  = errors.New("address: payment_id not supported on single addresses")
)

// creationError mirrors TariAddressError::CreationError(String), which
// carries a dynamic message in the real Rust enum.
type creationError struct {
	msg string
}

func (e *creationError) Error() string { return "address: could not create TariAddress: " + e.msg }

func newCreationError(msg string) error { return &creationError{msg: msg} }
