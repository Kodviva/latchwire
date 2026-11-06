package main

import "testing"

func TestInsideWindowsDir(t *testing.T) {
	const pf = `C:\Program Files`
	for p, want := range map[string]bool{
		`C:\Program Files\Latchwire\latchwire.exe`: true,
		`c:\program files\latchwire\LATCHWIRE.EXE`: true,
		`C:/Program Files/Latchwire/latchwire.exe`: true,
		`C:\Program Files Evil\latchwire.exe`:      false,
		`C:\Program Files`:                         false,
		`C:\Program Files\`:                        false,
		`C:\Users\me\Downloads\latchwire.exe`:      false,
		`C:\Program Files\..\Users\me\x.exe`:       false,
		`D:\Program Files\Latchwire\latchwire.exe`: false,
	} {
		if got := insideWindowsDir(p, pf); got != want {
			t.Errorf("insideWindowsDir(%q) = %v", p, got)
		}
	}
	if insideWindowsDir(`C:\x`, "") {
		t.Error("an empty directory holds nothing")
	}
}
