//go:build windows

package platform

import (
	"golang.org/x/sys/windows"
)

// OpenURL opens url in the system default browser via
// ShellExecute. Used for the in-app "illustrated guide" entry
// (the website's guide page). A failure is returned to the
// caller, which logs it and tells the user the address in
// plain text (teardown §1.7: a failed open must never be
// silent).
func OpenURL(url string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}
