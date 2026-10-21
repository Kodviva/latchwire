//go:build !darwin && !linux

package netmon

// NewSource reports that this OS has no network change source.
func NewSource() (Source, error) { return nil, errUnsupported }
