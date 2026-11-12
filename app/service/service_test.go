package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"

	"openproxy/app/service"
)

// fakeEngine implements service.Engine with scripted handshakes.
type fakeEngine struct {
	latency   map[string]time.Duration // nodeID -> latency; absent = handshake failure
	startErr  error
	stopErr   error
	started   *specnode.Node
	startOpts kernel.PlatformOptions
	stopped   bool
	traffic   *kernel.TrafficStats
}

func (f *fakeEngine) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		KernelID: "fake", KernelVersion: "0",
		Platform: kernel.PlatformCapabilities{Platform: "test"},
	}
}

func (f *fakeEngine) ValidateSpec(_ context.Context, n *specnode.Node) error {
	return n.Validate()
}

func (f *fakeEngine) StartNode(_ context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.started = n
	f.startOpts = opts
	return nil
}

func (f *fakeEngine) Stop(_ context.Context) error { f.stopped = true; return f.stopErr }

func (f *fakeEngine) Status() kernel.Status {
	if f.started != nil && !f.stopped {
		return kernel.Status{State: kernel.StateRunning, ActiveNodeID: f.started.ID}
	}
	return kernel.Status{State: kernel.StateIdle}
}

func (f *fakeEngine) TestHandshakeNode(_ context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	res := &kernel.HandshakeResult{NodeID: n.ID, TestedAt: time.Now()}
	if lat, ok := f.latency[n.ID]; ok {
		res.OK = true
		res.Latency = lat
	} else {
		res.Error = kernel.NewError(kernel.KindHandshakeFailed, "TestHandshake", "scripted failure", nil)
	}
	return res, nil
}

func (f *fakeEngine) QueryTraffic(_ context.Context) (*kernel.TrafficStats, error) {
	if f.traffic != nil {
		return f.traffic, nil
	}
	return &kernel.TrafficStats{}, nil
}

func (f *fakeEngine) MixedAddr() string {
	if f.started != nil {
		return "127.0.0.1:2080"
	}
	return ""
}

func ssNode(id, method string) *specnode.Node {
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            id,
		Name:          id,
		Protocol:      specnode.ProtocolShadowsocks,
		Server:        "127.0.0.1",
		Port:          8388,
		Source:        specnode.SourceRef{Kind: "manual", Ref: "test", Authorization: "user-provided"},
		Shadowsocks:   &specnode.CredShadowsocks{Method: method, Password: "pw"},
	}
}

func newTestService(t *testing.T, eng service.Engine) (*service.Service, *service.Store) {
	t.Helper()
	store, err := service.OpenStore("") // in-memory
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return service.New(store, eng), store
}

func TestWeakEncryptionClassification(t *testing.T) {
	if !service.WeakEncryption(ssNode("a", "rc4-md5")) {
		t.Error("rc4-md5 must be weak")
	}
	if !service.WeakEncryption(ssNode("b", "aes-256-cfb")) {
		t.Error("aes-256-cfb must be weak")
	}
	if !service.WeakEncryption(ssNode("c", "chacha20-ietf")) {
		t.Error("chacha20-ietf must be weak")
	}
	if service.WeakEncryption(ssNode("d", "aes-256-gcm")) {
		t.Error("aes-256-gcm is AEAD, must not be weak")
	}
	if service.WeakEncryption(ssNode("e", "2022-blake3-aes-256-gcm")) {
		t.Error("SS2022 method must not be weak")
	}
	codes := service.WarningCodes(ssNode("a", "rc4-md5"))
	if len(codes) != 1 || codes[0] != "weak-encryption" {
		t.Errorf("WarningCodes = %v, want [weak-encryption]", codes)
	}
}

func TestAutoSelectDeprioritizesWeak(t *testing.T) {
	fast, slow := 10.0, 200.0
	weakFast := ssNode("weak-fast", "rc4-md5")
	weakFast.LastTest = &specnode.LastTest{At: "t", OK: true, LatencyMs: &fast}
	strongSlow := ssNode("strong-slow", "aes-256-gcm")
	strongSlow.LastTest = &specnode.LastTest{At: "t", OK: true, LatencyMs: &slow}
	dead := ssNode("dead", "aes-256-gcm")
	dead.LastTest = &specnode.LastTest{At: "t", OK: false}
	untested := ssNode("untested", "aes-256-gcm")

	got := service.AutoSelect([]service.NodeRecord{
		{Node: weakFast}, {Node: strongSlow}, {Node: dead}, {Node: untested},
	})
	if got == nil || got.ID != "strong-slow" {
		t.Fatalf("AutoSelect = %v, want strong-slow (weak must never be the default pick while a working non-weak node exists)", got)
	}

	// Only the weak node works -> it may be selected (documented fallback).
	got = service.AutoSelect([]service.NodeRecord{{Node: weakFast}, {Node: dead}})
	if got == nil || got.ID != "weak-fast" {
		t.Fatalf("AutoSelect fallback = %v, want weak-fast", got)
	}

	// Nothing tested OK -> nil.
	if got := service.AutoSelect([]service.NodeRecord{{Node: dead}, {Node: untested}}); got != nil {
		t.Fatalf("AutoSelect with no OK node = %v, want nil", got)
	}
}

func TestStoreRoundTripAndReorder(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/store.json"
	st, err := service.OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	st.AddNode(ssNode("n1", "aes-256-gcm"), nil)
	st.AddNode(ssNode("n2", "rc4-md5"), []string{"weak-encryption"})
	st.AddGroup("g1")
	if err := st.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	st2, err := service.OpenStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	doc := st2.Snapshot()
	if len(doc.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(doc.Nodes))
	}
	rec, ok := st2.NodeByID("n2")
	if !ok || len(rec.Warnings) != 1 || rec.Warnings[0] != "weak-encryption" {
		t.Errorf("n2 record warnings = %v (ok=%v)", rec.Warnings, ok)
	}
	// Re-importing the same node must not duplicate it.
	st2.AddNode(ssNode("n1", "aes-256-gcm"), nil)
	if len(st2.Snapshot().Nodes) != 2 {
		t.Error("re-import duplicated a node")
	}
	if !st2.MoveNode("n2", -1) {
		t.Fatal("MoveNode failed")
	}
	if st2.Snapshot().Nodes[0].Node.ID != "n2" {
		t.Error("MoveNode did not reorder")
	}
	if !st2.DeleteNode("n1") || st2.DeleteNode("n1") {
		t.Error("DeleteNode semantics broken")
	}
}

func TestImportLinksAndWeakWarningFlow(t *testing.T) {
	svc, _ := newTestService(t, &fakeEngine{})
	// Legacy ss link (SIP002, base64 userinfo of aes-256-cfb:pw).
	rep := svc.ImportText("ss://YWVzLTI1Ni1jZmI6cHc@127.0.0.1:8388#legacy\nss://YWVzLTI1Ni1nY206cHc@127.0.0.1:8389#modern\nnot-a-link")
	if rep.OK() != 2 {
		t.Fatalf("imported = %d, want 2 (failures: %+v)", rep.OK(), rep.Failed)
	}
	if len(rep.Failed) != 1 {
		t.Fatalf("failures = %+v, want exactly the bogus line", rep.Failed)
	}
	views := svc.Nodes(service.AllGroups)
	if len(views) != 2 {
		t.Fatalf("views = %d", len(views))
	}
	var weakViews, strongViews int
	for _, v := range views {
		if v.Weak {
			weakViews++
			found := false
			for _, c := range v.Record.Warnings {
				if c == "weak-encryption" {
					found = true
				}
			}
			if !found {
				t.Errorf("weak node %s lacks the stored weak-encryption warning", v.Record.Node.ID)
			}
		} else {
			strongViews++
		}
	}
	if weakViews != 1 || strongViews != 1 {
		t.Errorf("weak/strong = %d/%d, want 1/1", weakViews, strongViews)
	}
}

func TestConnectTestAndAutoSelectFlow(t *testing.T) {
	eng := &fakeEngine{latency: map[string]time.Duration{}}
	svc, _ := newTestService(t, eng)
	svc.ImportText("ss://YWVzLTI1Ni1jZmI6cHc@127.0.0.1:8388#legacy\nss://YWVzLTI1Ni1nY206cHc@127.0.0.1:8389#modern")
	views := svc.Nodes(service.AllGroups)
	ids := map[string]string{} // name -> id
	for _, v := range views {
		ids[v.Record.Node.Name] = v.Record.Node.ID
		eng.latency[v.Record.Node.ID] = 50 * time.Millisecond
	}
	// Weak node is *faster*; auto-select must still pick the AEAD one.
	eng.latency[ids["legacy"]] = 5 * time.Millisecond
	if _, err := svc.TestGroup(context.Background(), service.AllGroups); err != nil {
		t.Fatalf("TestGroup: %v", err)
	}
	n, err := svc.AutoSelectAndConnect(context.Background(), service.AllGroups)
	if err != nil {
		t.Fatalf("AutoSelectAndConnect: %v", err)
	}
	if n.ID != ids["modern"] {
		t.Fatalf("auto-selected %s, want the AEAD node %s", n.ID, ids["modern"])
	}
	if eng.started == nil || eng.started.ID != ids["modern"] {
		t.Fatal("engine was not started with the auto-selected node")
	}
	if svc.Status().State != kernel.StateRunning {
		t.Error("status should be running after connect")
	}
	if err := svc.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if !eng.stopped {
		t.Error("engine.Stop was not called")
	}
}

func TestConnectSurfacesPlatformRefusal(t *testing.T) {
	platformErr := kernel.NewError(kernel.KindPlatformUnavailable, "Start", "TUN unavailable", nil)
	eng := &fakeEngine{startErr: platformErr}
	svc, _ := newTestService(t, eng)
	svc.ImportText("ss://YWVzLTI1Ni1nY206cHc@127.0.0.1:8389#modern")
	views := svc.Nodes(service.AllGroups)
	err := svc.Connect(context.Background(), views[0].Record.Node.ID)
	if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Fatalf("Connect error = %v, want platform_unavailable kind preserved", err)
	}
}

func TestServiceWithoutEngine(t *testing.T) {
	svc, _ := newTestService(t, nil)
	svc.ImportText("ss://YWVzLTI1Ni1nY206cHc@127.0.0.1:8389#modern")
	views := svc.Nodes(service.AllGroups)
	if _, err := svc.TestNode(context.Background(), views[0].Record.Node.ID); !errors.Is(err, service.ErrNoEngine) {
		t.Errorf("TestNode without engine = %v, want ErrNoEngine", err)
	}
	if err := svc.Connect(context.Background(), views[0].Record.Node.ID); !errors.Is(err, service.ErrNoEngine) {
		t.Errorf("Connect without engine = %v, want ErrNoEngine", err)
	}
	if !strings.Contains(svc.Logs().Lines()[0], "import") {
		t.Error("import should be logged")
	}
}
