package platform

import "fmt"

// Windows update installer (Step 16) — PLACEHOLDER, pending
// real-machine verification.
//
// Intended production behavior: launch the verified installer
// artifact (the release .exe produced by the Step 15 pipeline)
// via ShellExecute, then let the running client exit so the
// installer can replace the binary in place. The artifact has
// already passed SHA-256 + Ed25519 verification in the service
// layer before this point is reached.
//
// Why it does not do that yet: there is no Windows machine in
// the build sandbox, so the launch-and-replace sequence
// (elevation prompt, file locking by the running process,
// rollback on installer failure) cannot be verified here.
// Per the honesty contract it therefore reports unavailable;
// the client surfaces "download the new version manually"
// instead of faking an in-app install. Enabling this is a
// Step 19 (public beta) real-machine item, recorded in
// docs/step16-更新机制.md.
type winInstaller struct{}

func (winInstaller) Available() bool { return false }

func (winInstaller) Install(string) error {
	return fmt.Errorf("%w: Windows in-app install is implemented as a placeholder pending real-machine verification (Step 16)", ErrUnavailable)
}
