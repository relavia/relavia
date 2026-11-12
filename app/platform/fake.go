package platform

// In-memory fakes: used by unit tests and by development builds
// on platforms without a real implementation, so the full client
// logic (service -> platform calls) stays exercisable everywhere.

// FakeSystemProxy records calls in memory.
type FakeSystemProxy struct {
	Settings      ProxySettings
	AvailableFlag bool
	SetCalls      int
	ClearCalls    int
}

// NewFakeSystemProxy returns an available fake with proxy off.
func NewFakeSystemProxy() *FakeSystemProxy { return &FakeSystemProxy{AvailableFlag: true} }

func (f *FakeSystemProxy) Get() (ProxySettings, error) { return f.Settings, nil }

func (f *FakeSystemProxy) Set(server string) error {
	f.SetCalls++
	f.Settings = ProxySettings{Enabled: true, Server: server, Bypass: f.Settings.Bypass}
	return nil
}

func (f *FakeSystemProxy) Clear() error {
	f.ClearCalls++
	f.Settings.Enabled = false
	f.Settings.Server = ""
	return nil
}

func (f *FakeSystemProxy) Available() bool { return f.AvailableFlag }

// FakeTUN reports a fixed availability.
type FakeTUN struct {
	Avail bool
	Info  string
}

func (f *FakeTUN) Available() bool { return f.Avail }
func (f *FakeTUN) Detail() string  { return f.Info }

// FakeTray records tray interactions.
type FakeTray struct {
	Events        TrayEvents
	Shown         bool
	Tooltip       string
	Menu          []TrayMenuItem
	AvailableFlag bool
}

// NewFakeTray returns an available recording tray.
func NewFakeTray(ev TrayEvents) *FakeTray { return &FakeTray{Events: ev, AvailableFlag: true} }

func (f *FakeTray) Show(tooltip string) error    { f.Shown = true; f.Tooltip = tooltip; return nil }
func (f *FakeTray) SetMenu(items []TrayMenuItem) { f.Menu = append([]TrayMenuItem{}, items...) }
func (f *FakeTray) SetTooltip(tooltip string)    { f.Tooltip = tooltip }
func (f *FakeTray) Hide() error                  { f.Shown = false; return nil }
func (f *FakeTray) Available() bool              { return f.AvailableFlag }

// Click simulates a menu activation (tests).
func (f *FakeTray) Click(id string) {
	if f.Events.OnMenuItem != nil {
		f.Events.OnMenuItem(id)
	}
}

// UnsupportedSystemProxy always reports unavailable (non-Windows
// builds in this step; Linux/macOS implementations are phase-2).
type UnsupportedSystemProxy struct{}

func (UnsupportedSystemProxy) Get() (ProxySettings, error) { return ProxySettings{}, ErrUnavailable }
func (UnsupportedSystemProxy) Set(string) error            { return ErrUnavailable }
func (UnsupportedSystemProxy) Clear() error                { return ErrUnavailable }
func (UnsupportedSystemProxy) Available() bool             { return false }

// UnsupportedTUN always reports unavailable.
type UnsupportedTUN struct{ Why string }

func (u UnsupportedTUN) Available() bool { return false }
func (u UnsupportedTUN) Detail() string  { return u.Why }

// NoopTray satisfies Tray without any OS presence (non-Windows
// development builds): calls succeed silently, Available is false
// so the UI does not claim a tray exists.
type NoopTray struct{ Events TrayEvents }

func (NoopTray) Show(string) error      { return nil }
func (NoopTray) SetMenu([]TrayMenuItem) {}
func (NoopTray) SetTooltip(string)      {}
func (NoopTray) Hide() error            { return nil }
func (NoopTray) Available() bool        { return false }
