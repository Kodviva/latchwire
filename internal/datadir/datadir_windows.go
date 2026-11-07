package datadir

import (
	"errors"
	"fmt"
	"io/fs"
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
// SYSTEM or Administrators own it. It then gives the directory and all that
// is in it dirSDDL and Administrators as owner: the daemon reads these files
// without further checks, since Windows has no mode bits to look at. A
// reparse point anywhere in the tree is not something the daemon made and
// is refused.
//
// Each object is opened once, without following reparse points, and judged
// and changed through that handle: a name that is swapped for a junction
// between a check and a change could otherwise hand the change to whatever
// the junction points at.
func Secure() error { return SecureDir(Dir()) }

// SecureDir is Secure for the directory dir: tests give it one of theirs.
func SecureDir(dir string) error {
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
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	// An object an elevated administrator created belongs to that user, so
	// only the top directory's owner decides; a directory just created here
	// is ours whoever owns it.
	if err := lockDown(dir, !created, dacl, admins); err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		return lockDown(p, false, dacl, admins)
	})
}

// lockDown gives the file or directory p the DACL and owner. With
// checkOwner, an owner that is not trusted is refused first.
func lockDown(p string, checkOwner bool, dacl *windows.ACL, owner *windows.SID) error {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("datadir: opening %s: %w", p, err)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("datadir: reading %s: %w", p, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf(msg.DataDirUntrustedFmt, p)
	}
	if checkOwner {
		cur, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("datadir: reading the owner of %s: %w", p, err)
		}
		sid, _, err := cur.Owner()
		if err != nil {
			return fmt.Errorf("datadir: reading the owner of %s: %w", p, err)
		}
		if !trusted(sid) {
			return fmt.Errorf(msg.DataDirUntrustedFmt, p)
		}
	}
	si := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, si, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("datadir: permissions of %s: %w", p, err)
	}
	return nil
}
