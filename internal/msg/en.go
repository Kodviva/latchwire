// Package msg holds user-facing message strings. They are flat constants so
// they can later be moved behind an i18n layer without touching call sites.
// Format strings never take secret values: keys and PINs are never echoed.
package msg

const (
	// KeyRefInvalidFmt takes the offending reference string.
	KeyRefInvalidFmt = "invalid key reference %q: expected piv://<decimal serial>/<slot 82-95>"

	ConfigPrivateKeyNotAllowed = "PrivateKey is not allowed: the private key stays in the hardware token, use KeyRef = piv://<serial>/<slot>"
	ConfigNoIdentity           = "no hardware key configured: add KeyRef = piv://<serial>/<slot> to [Interface] or an [Identity] section"
	ConfigTooLargeFmt          = "configuration is larger than %d bytes"

	// ConfigLineFmt takes a line number and a wrapped error.
	ConfigLineFmt = "line %d: %w"

	// The formats below take a key or section name, never a value.
	ConfigHookNotSupportedFmt = "%s is not supported: Latchwire never runs commands from tunnel configurations"
	ConfigUnknownKeyFmt       = "unknown key %s in [%s]"
	ConfigUnknownSectionFmt   = "unknown section [%s]"
	ConfigKeyOutsideSection   = "key found before any section header"
	ConfigMalformedLine       = "expected Key = Value or [Section]"
	ConfigDuplicateKeyFmt     = "%s is set more than once"
	ConfigInvalidValueFmt     = "invalid value for %s"
	ConfigMissingKeyFmt       = "[%s] section is missing %s"
	ConfigDuplicateSectionFmt = "[%s] section appears more than once"
	ConfigDuplicatePeer       = "the same PublicKey is used by more than one [Peer]"
	ConfigMixedIdentities     = "KeyRef and Address belong in [Interface] or in [Identity] sections, not both"
)
