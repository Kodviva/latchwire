// Package msg holds user-facing message strings. They are flat constants so
// they can later be moved behind an i18n layer without touching call sites.
// Format strings never take secret values: keys and PINs are never echoed.
package msg

const (
	// KeyRefInvalidFmt takes the offending reference string.
	KeyRefInvalidFmt = "invalid key reference %q: expected piv://<decimal serial>/<slot 82-95>"

	ConfigPrivateKeyNotAllowed = "PrivateKey is not allowed: the private key stays in the hardware token, use KeyRef = piv://<serial>/<slot>"
	ConfigNoIdentity           = "no hardware key configured: add KeyRef = piv://<serial>/<slot> and its PublicKey to [Interface] or an [Identity] section"
	ConfigTooLargeFmt          = "configuration is larger than %d bytes"

	// ConfigLineFmt takes a line number and a wrapped error.
	ConfigLineFmt = "line %d: %w"

	// The formats below take a key or section name, never a value.
	ConfigHookNotSupportedFmt    = "%s is not supported: Latchwire never runs commands from tunnel configurations"
	ConfigUnknownKeyFmt          = "unknown key %s in [%s]"
	ConfigUnknownSectionFmt      = "unknown section [%s]"
	ConfigKeyOutsideSection      = "key found before any section header"
	ConfigMalformedLine          = "expected Key = Value or [Section]"
	ConfigDuplicateKeyFmt        = "%s is set more than once"
	ConfigInvalidValueFmt        = "invalid value for %s"
	ConfigMissingKeyFmt          = "[%s] section is missing %s"
	ConfigDuplicateSectionFmt    = "[%s] section appears more than once"
	ConfigDuplicatePeer          = "the same PublicKey is used by more than one [Peer]"
	ConfigMixedIdentities        = "KeyRef and Address belong in [Interface] or in [Identity] sections, not both"
	ConfigPublicKeyWithoutKeyRef = "PublicKey in [Interface] is the public key of the KeyRef there; with [Identity] sections put each PublicKey in its section"

	// YubiKey PIV backend. None of these formats take a PIN, PUK or key.
	PIVCardNotFound          = "no YubiKey with that serial number was found (is it plugged in, or in use by another program?)"
	PIVFirmwareTooOld        = "YubiKey firmware is too old: X25519 keys in PIV need firmware 5.7.0 or later"
	PIVSlotOccupied          = "the slot already holds a key; use --force to replace it (the old key is destroyed)"
	PIVNoFreeSlot            = "no free retired slot (82-95) is left on this YubiKey"
	PIVSlotEmpty             = "the slot holds no key"
	PIVFreshCard             = "this YubiKey still uses the factory management key: give the current PIN and PUK and a new PIN and PUK (6-8 characters each, not the factory values) so it can be secured first"
	PIVManagementKeyRequired = "the management key is needed: give the PIN if the management key is stored on the YubiKey protected by the PIN, or give the management key"
	PIVImportedKey           = "the key in this slot was imported, not generated on the YubiKey; Latchwire only uses keys generated on the card"
	PIVNotX25519             = "the key in this slot is not an X25519 key"
	PIVSlotOutOfRangeFmt     = "slot %02x is not a retired key management slot (82-95)"
	PIVWrongPUKFmt           = "wrong PUK, %d retries left"
	PIVPUKBlocked            = "the PUK is blocked"
	PIVStoredKeyMismatch     = "the management key stored on the YubiKey could not be read back correctly, so the factory management key was kept"
	PIVPIVManFlagFailed      = "the new management key is set and stored on the YubiKey under the PIN, but ykman's \"protected by PIN\" flag could not be written"
	// PIVPINAlreadyChanged and PIVPINAndPUKAlreadyChanged prefix errors from
	// securing a fresh card after the PIN (and PUK) were already changed.
	PIVPINAlreadyChanged       = "the PIN has already been changed to the new PIN (the PUK has not)"
	PIVPINAndPUKAlreadyChanged = "the PIN and PUK have already been changed to the new values"
	PIVSecretTooLong           = "a PIN or PUK longer than 8 bytes was given"
	PIVPINTooLong              = "the PIN entered is longer than 8 bytes"
	PIVUnsupportedPolicy       = "the key in this slot does not use PIN policy \"once\" and touch policy \"never\"; Latchwire only uses such keys"
	PIVEmptyPIN                = "no PIN was entered"
	PIVUnexpectedPublicKey     = "the YubiKey returned an unexpected public key type"

	// User-session agent. None of these formats take a PIN or key material.
	LastPINRetry = "warning: only one PIN attempt is left; a wrong PIN now blocks the PIV PIN and only the PUK can unblock it"
	// AgentPINPromptFmt takes the serial, the slot and the retries left.
	AgentPINPromptFmt = "Latchwire: PIN for YubiKey %d slot %02x (%d attempts left): "
	// AgentWrongPINFmt takes the retries left.
	AgentWrongPINFmt     = "wrong PIN, %d attempts left"
	AgentPINBlocked      = "the YubiKey PIN is blocked; unblock it with the PUK (for example: ykman piv access unblock-pin)"
	AgentPINRequired     = "the YubiKey PIN is needed but was not entered"
	AgentCardUnavailable = "the YubiKey is not available (was it removed?)"
	AgentBadPeer         = "peer must be the base64 encoding of a 32-byte X25519 public key"
	AgentBadRequest      = "malformed request"
	AgentLowOrderPeer    = "the peer public key is a low-order point"
	AgentNoTTY           = "no terminal is available to ask for the PIN"
	AgentRequestExpired  = "the request expired before the YubiKey could be used"
	// AgentUntrustedDaemonFmt takes the uid of the socket's owner process.
	AgentUntrustedDaemonFmt = "refusing the service socket: it is served by uid %d, not by root or this user"
)

// Network configuration.
const (
	NetFullTunnelUnsupported = "routing all traffic through the tunnel (AllowedIPs 0.0.0.0/0 or ::/0) is not supported yet; list the networks to reach instead"
	NetAlreadyApplied        = "network configuration is already applied to this interface"
)

// Tunnel daemon. None of these formats take key material or a PIN.
const (
	DaemonAdminOnly      = "permission denied: only an administrator can add or remove tunnels"
	DaemonForbidden      = "permission denied: run this as an administrator, or start latchwire agent as this user first"
	DaemonBadRequest     = "malformed request"
	DaemonTunnelNotFound = "no tunnel with that name"
	DaemonTunnelExists   = "a tunnel with that name already exists; remove it first"
	DaemonInvalidName    = "invalid tunnel name: use 1-15 letters, digits or _=+.- and do not start with a dot"
	DaemonNoCard         = "none of the tunnel's YubiKeys is available: plug one in and make sure latchwire agent is running"
	DaemonAgentGone      = "the agent holding the YubiKey is not connected"
	DaemonBadAgentReply  = "the agent sent a malformed reply"
	DaemonConnectAborted = "connecting was interrupted: the tunnel was disconnected or its YubiKey was removed"
	DaemonNotYourTunnel  = "permission denied: this tunnel is in use with another user's YubiKey"
	// DaemonKeyMismatchFmt and DaemonProofFailedFmt take the KeyRef.
	DaemonKeyMismatchFmt = "the YubiKey answering for %s does not hold the PublicKey configured for this tunnel; refusing to connect"
	DaemonProofFailedFmt = "the agent answering for %s could not prove that it holds the private key of the configured PublicKey; refusing to connect"
	// DaemonResolveFmt takes the endpoint host name.
	DaemonResolveFmt = "cannot resolve the endpoint host %s"
	// DaemonConnectFailedFmt and DaemonStoreFailedFmt take an error.
	DaemonConnectFailedFmt = "could not bring the tunnel up: %v"
	DaemonStoreFailedFmt   = "could not save the tunnel configuration: %v"
)
