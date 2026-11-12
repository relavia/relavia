package platform

import (
	"errors"
	"testing"
)

type fakeInstallBinder struct {
	calls    int
	lastPath string
	err      error
}

func (f *fakeInstallBinder) InstallUpdate(path string) error {
	f.calls++
	f.lastPath = path
	return f.err
}

func TestBridgeInstallerWithoutBinderIsUnavailable(t *testing.T) {
	RegisterInstallBinder(nil)
	inst := BridgeInstaller{}
	if inst.Available() {
		t.Fatal("bridge installer must be unavailable with no shell binder registered")
	}
	if err := inst.Install("/tmp/relavia.apk"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Install err = %v, want ErrUnavailable", err)
	}
}

func TestBridgeInstallerDelegatesToBinder(t *testing.T) {
	b := &fakeInstallBinder{}
	RegisterInstallBinder(b)
	t.Cleanup(func() { RegisterInstallBinder(nil) })

	inst := BridgeInstaller{}
	if !inst.Available() {
		t.Fatal("bridge installer must be available once the shell binder is registered")
	}
	if err := inst.Install("/tmp/relavia-0.2.0.apk"); err != nil {
		t.Fatal(err)
	}
	if b.calls != 1 || b.lastPath != "/tmp/relavia-0.2.0.apk" {
		t.Errorf("binder calls = %d, lastPath = %q", b.calls, b.lastPath)
	}

	b.err = errors.New("user dismissed the system installer")
	if err := inst.Install("/tmp/relavia-0.2.0.apk"); err == nil || err.Error() != b.err.Error() {
		t.Errorf("binder error not propagated: %v", err)
	}
}

func TestFakeInstallerRecordsCalls(t *testing.T) {
	f := NewFakeInstaller()
	if !f.Available() {
		t.Fatal("fake installer should default to available")
	}
	if err := f.Install("/tmp/x.exe"); err != nil {
		t.Fatal(err)
	}
	if f.InstallCalls != 1 || f.LastPath != "/tmp/x.exe" {
		t.Errorf("calls = %d, lastPath = %q", f.InstallCalls, f.LastPath)
	}
	f.FailInstall = errors.New("boom")
	if err := f.Install("/tmp/x.exe"); err == nil {
		t.Error("FailInstall not honored")
	}
}

func TestUnsupportedInstallerIsHonest(t *testing.T) {
	inst := UnsupportedInstaller{Why: "test"}
	if inst.Available() {
		t.Fatal("unsupported installer must report unavailable")
	}
	if err := inst.Install("/tmp/x"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
}
