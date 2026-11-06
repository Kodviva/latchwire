package main

import (
	"context"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Kodviva/latchwire/internal/ipc"
)

// userCallTimeout bounds one lookup in the daemon's user table.
const userCallTimeout = 5 * time.Second

func userCall(method string, in ipc.UserInfo) (ipc.UserInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), userCallTimeout)
	defer cancel()
	var out ipc.UserInfo
	c, err := dialDaemon(ctx)
	if err != nil {
		return out, err
	}
	defer c.Close()
	return out, c.Call(ctx, method, in, &out)
}

// lookupUserID is env.lookupUser: the system knows the SID of a user name,
// and the daemon, which holds the table, its uid.
func lookupUserID(name string) (uint32, error) {
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return 0, err
	}
	u, err := userCall(ipc.MethodUserID, ipc.UserInfo{SID: sid.String()})
	return u.UID, err
}

// lookupUserName is env.userName: DOMAIN\name, or "" when unknown.
func lookupUserName(uid uint32) string {
	u, err := userCall(ipc.MethodUserSID, ipc.UserInfo{UID: uid})
	if err != nil {
		return ""
	}
	sid, err := windows.StringToSid(u.SID)
	if err != nil {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
