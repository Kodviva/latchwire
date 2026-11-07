package datadir

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The tests run elevated, as the service does: CI runners are.

var aceRE = regexp.MustCompile(`\(([^)]*)\)`)

// checkLocked fails unless p is owned by Administrators and its DACL is
// protected and grants full control to SYSTEM and Administrators only.
func checkLocked(t *testing.T, p string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	sddl := sd.String()
	if !strings.HasPrefix(sddl, "O:BA") {
		t.Errorf("%s: owner is not Administrators: %s", p, sddl)
	}
	if !strings.Contains(sddl, "D:P") {
		t.Errorf("%s: DACL not protected from inheritance: %s", p, sddl)
	}
	trustees := map[string]bool{}
	for _, m := range aceRE.FindAllStringSubmatch(sddl, -1) {
		f := strings.Split(m[1], ";")
		if len(f) < 6 || f[0] != "A" || f[2] != "FA" {
			t.Errorf("%s: unexpected ACE %q in %s", p, m[1], sddl)
			continue
		}
		trustees[f[5]] = true
	}
	if len(trustees) != 2 || !trustees["SY"] || !trustees["BA"] {
		t.Errorf("%s: DACL is not SYSTEM and Administrators only: %s", p, sddl)
	}
}

// setSDDL gives p the security descriptor sddl (owner and DACL).
func setSDDL(t *testing.T, p, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	si := windows.SECURITY_INFORMATION(0)
	owner, _, err := sd.Owner()
	if err == nil && owner != nil {
		si |= windows.OWNER_SECURITY_INFORMATION
	}
	dacl, _, err := sd.DACL()
	if err == nil && dacl != nil {
		si |= windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, si, owner, nil, dacl, nil); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
}

func currentUserSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

func TestSecureDirCreatesLockedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	checkLocked(t, dir)
	// What the daemon creates later inherits the same protection.
	f := filepath.Join(dir, "journal.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	checkLocked(t, f)
}

// A file that someone opened up to Everyone is locked down again.
func TestSecureDirLocksDownContents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "tunnels")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "wg0.conf")
	if err := os.WriteFile(f, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setSDDL(t, sub, "D:P(A;OICI;FA;;;WD)")
	setSDDL(t, f, "O:"+currentUserSID(t)+"D:P(A;;FA;;;WD)")
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	checkLocked(t, sub)
	checkLocked(t, f)
}

// A directory that exists with an owner other than SYSTEM or
// Administrators may have been planted by a user: it is refused, untouched.
func TestSecureDirRefusesUntrustedOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	user := currentUserSID(t)
	setSDDL(t, dir, "O:"+user+"D:P(A;OICI;FA;;;WD)")
	err := SecureDir(dir)
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("SecureDir = %v, want a refusal naming %s", err, dir)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	// Compared as SIDs: SDDL writes well-known accounts by alias (LA for
	// the built-in Administrator a CI runner may be).
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := windows.StringToSid(user); !owner.Equals(want) || !strings.Contains(sd.String(), ";;;WD)") {
		t.Errorf("the refused directory was changed: %s", sd.String())
	}
}

// A junction inside the directory is refused, and what it points at keeps
// its permissions.
func TestSecureDirRefusesJunction(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	setSDDL(t, target, "D:P(A;OICI;FA;;;WD)")
	link := filepath.Join(dir, "tunnels")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
	err := SecureDir(dir)
	if err == nil || !strings.Contains(err.Error(), link) {
		t.Fatalf("SecureDir = %v, want a refusal naming %s", err, link)
	}
	sd, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if got := sd.String(); !strings.Contains(got, ";;;WD)") {
		t.Errorf("the junction's target was changed: %s", got)
	}
}
