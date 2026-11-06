package datadir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Kodviva/latchwire/internal/msg"
)

// dirSDDL gives SYSTEM and Administrators full control, inherited by what
// is created below; nothing is inherited from %ProgramData%.
const dirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// Dir returns %ProgramData%\Latchwire. The folder is asked of the system,
// never of the environment, which a service does not need to trust.
var Dir = sync.OnceValue(func() string {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Latchwire")
})

// trusted reports whether sid may own the data directory.
func trusted(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// Secure creates the data directory or, when it exists, refuses it unless
// SYSTEM or Administrators own it and it is a real directory. Either way it
// ends with dirSDDL in place, so what an earlier version or a person left
// open is closed.
func Secure() error {
	dir := Dir()
	sd, err := windows.SecurityDescriptorFromString(dirSDDL)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	created := true
	if err := windows.CreateDirectory(name, &sa); err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("datadir: creating %s: %w", dir, err)
		}
		created = false
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	if created {
		// An elevated administrator's objects may belong to the user;
		// SYSTEM's are SYSTEM's, which is trusted already.
		if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
			return fmt.Errorf("datadir: owner of %s: %w", dir, err)
		}
	} else {
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeIrregular != 0 {
			return fmt.Errorf(msg.DataDirUntrustedFmt, dir)
		}
		cur, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("datadir: reading the owner of %s: %w", dir, err)
		}
		owner, _, err := cur.Owner()
		if err != nil {
			return fmt.Errorf("datadir: reading the owner of %s: %w", dir, err)
		}
		if !trusted(owner) {
			return fmt.Errorf(msg.DataDirUntrustedFmt, dir)
		}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("datadir: permissions of %s: %w", dir, err)
	}
	return nil
}
