// Package datadir locates the directory the Windows service keeps its state
// in. Unix keeps its paths in the packages that use them; Dir is empty there
// and Secure does nothing.
//
// On Windows every user may create directories below %ProgramData%, so the
// directory's owner and DACL are checked before anything in it is trusted:
// the journal holds commands that SYSTEM runs at start.
package datadir
