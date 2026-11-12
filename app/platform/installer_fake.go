package platform

// FakeInstaller records Install calls in memory. Used by unit
// tests and development builds so service-level update logic
// stays exercisable everywhere. It installs NOTHING and never
// pretends to.
type FakeInstaller struct {
	AvailableFlag bool
	InstallCalls  int
	LastPath      string
	// FailInstall injects an Install error (fault injection).
	FailInstall error
}

func NewFakeInstaller() *FakeInstaller { return &FakeInstaller{AvailableFlag: true} }

func (f *FakeInstaller) Available() bool { return f.AvailableFlag }

func (f *FakeInstaller) Install(path string) error {
	f.InstallCalls++
	f.LastPath = path
	return f.FailInstall
}
