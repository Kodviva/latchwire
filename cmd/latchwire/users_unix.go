//go:build !windows

package main

import (
	"errors"
	"os/user"
	"strconv"
)

// lookupUserID is env.lookupUser in production.
func lookupUserID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, errors.New("not a numeric uid")
	}
	return uint32(n), nil
}

// lookupUserName is env.userName in production.
func lookupUserName(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return ""
	}
	return u.Username
}
