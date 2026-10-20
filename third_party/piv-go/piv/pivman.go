// Latchwire addition (not upstream piv-go): ykman's "PIVMAN data" object.

package piv

import (
	"errors"
	"fmt"
)

// PIVManFlagMgmtKeyStored is ykman's PIVMAN flag bit meaning "the management
// key is stored in the PIN-protected data object (0x5FC109)". With it set,
// `ykman piv info` prints "Management key is stored on the YubiKey,
// protected by PIN." and ykman uses the PIN instead of asking for the key.
const PIVManFlagMgmtKeyStored byte = 0x02

// objPIVManData is ykman's OBJECT_ID_PIVMAN_DATA. Its content is
// 0x80 { 0x81 flags(1 byte), 0x82 salt, 0x83 PIN timestamp }, all optional
// (yubikit/ykman piv.py, class PivmanData).
const objPIVManData = 0x5fff00

const (
	tagPIVManData  = 0x80
	tagPIVManFlags = 0x81
)

// PIVManFlags returns the flags byte of the PIVMAN data object, or 0 if the
// object or the flags field is absent. It needs no authentication.
func (yk *YubiKey) PIVManFlags() (byte, error) {
	end, txErr := yk.begin()
	if txErr != nil {
		return 0, txErr
	}
	defer end()
	content, err := ykGetObject(yk.tx, objPIVManData)
	if err != nil {
		return 0, err
	}
	fields, err := parsePIVManData(content)
	if err != nil {
		return 0, err
	}
	for _, f := range fields {
		if f.tag == tagPIVManFlags {
			return f.value[0], nil
		}
	}
	return 0, nil
}

// SetPIVManFlags sets (ORs in) flag bits in the PIVMAN data object, keeping
// every other flag bit and field as it is. It reads the object, merges, and
// writes it back authenticated with the management key key.
func (yk *YubiKey) SetPIVManFlags(key []byte, flags byte) error {
	end, txErr := yk.begin()
	if txErr != nil {
		return txErr
	}
	defer end()
	content, err := ykGetObject(yk.tx, objPIVManData)
	if err != nil {
		return err
	}
	merged, err := pivManSetFlags(content, flags)
	if err != nil {
		return err
	}
	if err := ykAuthenticate(yk.tx, key, yk.rand, yk.version); err != nil {
		return fmt.Errorf("authenticating with management key: %w", err)
	}
	return ykPutObject(yk.tx, objPIVManData, merged)
}

// ykGetObject returns the content of the 0x53 wrapper of a data object, or
// nil if the object does not exist.
func ykGetObject(tx *scTx, obj uint32) ([]byte, error) {
	cmd := apdu{
		instruction: insGetData,
		param1:      0x3f,
		param2:      0xff,
		data:        []byte{0x5c, 0x03, byte(obj >> 16), byte(obj >> 8), byte(obj)},
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("command failed: %w", err)
	}
	content, _, err := unmarshalASN1(resp, 1, 0x13) // tag 0x53
	if err != nil {
		return nil, fmt.Errorf("unmarshaling response: %v", err)
	}
	return content, nil
}

func ykPutObject(tx *scTx, obj uint32, content []byte) error {
	data := append([]byte{0x5c, 0x03, byte(obj >> 16), byte(obj >> 8), byte(obj)},
		marshalASN1(0x53, content)...)
	cmd := apdu{instruction: insPutData, param1: 0x3f, param2: 0xff, data: data}
	if _, err := tx.Transmit(cmd); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}

type pivManField struct {
	tag   byte
	value []byte
}

var errBadPIVManData = errors.New("malformed PIVMAN data object")

// parsePIVManData parses 0x80 { fields } with one-byte tags and short or
// 0x81/0x82 long-form lengths. Empty content means no fields.
func parsePIVManData(content []byte) ([]pivManField, error) {
	if len(content) == 0 {
		return nil, nil
	}
	tag, inner, rest, err := readTLV(content)
	if err != nil || tag != tagPIVManData || len(rest) != 0 {
		return nil, errBadPIVManData
	}
	var fields []pivManField
	for len(inner) > 0 {
		var f pivManField
		f.tag, f.value, inner, err = readTLV(inner)
		if err != nil {
			return nil, errBadPIVManData
		}
		if f.tag == tagPIVManFlags && len(f.value) != 1 {
			return nil, errBadPIVManData
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// pivManSetFlags returns content with flags ORed into the 0x81 field. Other
// fields keep their order and bytes; a missing 0x81 field is added first.
func pivManSetFlags(content []byte, flags byte) ([]byte, error) {
	fields, err := parsePIVManData(content)
	if err != nil {
		return nil, err
	}
	found := false
	for i := range fields {
		if fields[i].tag == tagPIVManFlags {
			fields[i].value = []byte{fields[i].value[0] | flags}
			found = true
		}
	}
	if !found {
		fields = append([]pivManField{{tagPIVManFlags, []byte{flags}}}, fields...)
	}
	var inner []byte
	for _, f := range fields {
		inner = append(inner, marshalASN1(f.tag, f.value)...)
	}
	return marshalASN1(tagPIVManData, inner), nil
}

func readTLV(b []byte) (tag byte, value, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errBadPIVManData
	}
	tag = b[0]
	if tag&0x1f == 0x1f {
		return 0, nil, nil, errBadPIVManData // multi-byte tags are not used here
	}
	n := int(b[1])
	b = b[2:]
	switch {
	case n < 0x80:
	case n == 0x81 && len(b) >= 1:
		n, b = int(b[0]), b[1:]
	case n == 0x82 && len(b) >= 2:
		n, b = int(b[0])<<8|int(b[1]), b[2:]
	default:
		return 0, nil, nil, errBadPIVManData
	}
	if len(b) < n {
		return 0, nil, nil, errBadPIVManData
	}
	return tag, b[:n], b[n:], nil
}
