package pbr

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testReadToken   = "01234567890123456789012345678901"
	testReportToken = "abcdefghijklmnopqrstuvwxyz012345"
)

func TestReconcileRetriesFailedApplyFromDurableState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := SaveState(state, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	runner := newFakeRunner()
	key := commandKey("wg", "set", "wg0", "peer", "peer", "allowed-ips", "45.57.22.134/32")
	runner.failures[key] = 1
	c := Config{Role: "controller", StateFile: state, API: APIConfig{Token: testReadToken, ReportToken: testReportToken}, Apply: []ApplyConfig{{Driver: "wg-route", Interface: "wg0", Peer: "peer"}}}
	runtime, err := newRuntime(c, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.reconcile(context.Background()); err == nil {
		t.Fatal("expected first apply failure")
	}
	if len(runtime.applied) != 0 {
		t.Fatal("failed state marked applied")
	}
	if err := runtime.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !Equal(runtime.applied, []string{"45.57.22.134/32"}) {
		t.Fatalf("applied=%v", runtime.applied)
	}
}

func TestReconcileRetriesFailedReportWithoutReapplying(t *testing.T) {
	var posts int32
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", req.Method)
		}
		if req.Header.Get("Authorization") != "Bearer "+testReportToken {
			t.Error("wrong report token")
		}
		status := http.StatusNoContent
		if atomic.AddInt32(&posts, 1) == 1 {
			status = http.StatusInternalServerError
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: ioutil.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})
	state := filepath.Join(t.TempDir(), "state")
	if err := SaveState(state, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	runner := newFakeRunner()
	c := Config{Role: "agent", StateFile: state, API: APIConfig{SourceURL: "http://controller.test/v1/networks", Token: testReadToken, ReportToken: testReportToken}, Apply: []ApplyConfig{{Driver: "wg-route", Interface: "wg0", Peer: "peer"}}}
	runtime, err := newRuntime(c, runner)
	if err != nil {
		t.Fatal(err)
	}
	runtime.client = &http.Client{Transport: transport}
	runtime.learned = []string{"45.57.22.134/32"}
	if err := runtime.reconcile(context.Background()); err == nil {
		t.Fatal("expected first report failure")
	}
	if err := runtime.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if posts != 2 {
		t.Fatalf("posts=%d", posts)
	}
	if got := strings.Count(runner.commandLines(), "wg set wg0 peer peer allowed-ips 45.57.22.134/32"); got != 1 {
		t.Fatalf("apply calls=%d\n%s", got, runner.commandLines())
	}
}

func TestAgentReplacesBootstrapStateAfterSuccessfulFetch(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := SaveState(state, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"version":1,"networks":["54.84.54.3/32"]}`
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: ioutil.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	runner := newFakeRunner()
	runtime, err := newRuntime(Config{
		Role:      "agent",
		StateFile: state,
		API:       APIConfig{SourceURL: "http://controller.test/v1/networks", Token: testReadToken, ReportToken: testReportToken},
		Apply:     []ApplyConfig{{Driver: "wg-route", Interface: "wg0", Peer: "peer"}},
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	runtime.client = &http.Client{Transport: transport}
	if err := runtime.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !Equal(runtime.desired, []string{"54.84.54.3/32"}) {
		t.Fatalf("desired=%v", runtime.desired)
	}
	if strings.Contains(runner.commandLines(), "allowed-ips 45.57.22.134/32,54.84.54.3/32") {
		t.Fatal("old bootstrap state was merged into fetched state")
	}
	if got := strings.Count(runner.commandLines(), "wg set wg0 peer peer allowed-ips"); got != 2 {
		t.Fatalf("apply calls=%d\n%s", got, runner.commandLines())
	}
}

func TestAPIUsesSeparateTokensAndRejectsBroadReports(t *testing.T) {
	runtime := &Runtime{config: Config{Role: "controller", StateFile: filepath.Join(t.TempDir(), "state"), MaxNetworks: 2, API: APIConfig{Token: testReadToken, ReportToken: testReportToken}}, runner: newFakeRunner(), desired: []string{"45.57.22.134/32"}}

	request := func(method, token string, payload APIResponse) int {
		var body *strings.Reader
		if method == http.MethodPost {
			encoded, _ := json.Marshal(payload)
			body = strings.NewReader(string(encoded))
		} else {
			body = strings.NewReader("")
		}
		req := httptest.NewRequest(method, "/v1/networks", body)
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		runtime.handler().ServeHTTP(response, req)
		return response.Code
	}
	if got := request(http.MethodGet, testReadToken, APIResponse{}); got != http.StatusOK {
		t.Fatalf("GET=%d", got)
	}
	if got := request(http.MethodGet, testReportToken, APIResponse{}); got != http.StatusUnauthorized {
		t.Fatalf("GET report token=%d", got)
	}
	if got := request(http.MethodPost, testReadToken, APIResponse{Version: 1, Networks: []string{"54.84.54.3/32"}}); got != http.StatusUnauthorized {
		t.Fatalf("POST read token=%d", got)
	}
	if got := request(http.MethodPost, testReportToken, APIResponse{Version: 1, Networks: []string{"8.8.8.8/0"}}); got != http.StatusBadRequest {
		t.Fatalf("POST /0=%d", got)
	}
	if got := request(http.MethodPost, testReportToken, APIResponse{Version: 1, Networks: []string{"23.23.189.144/28"}}); got != http.StatusBadRequest {
		t.Fatalf("POST /28=%d", got)
	}
	if got := request(http.MethodPost, testReportToken, APIResponse{Version: 1, Networks: []string{"54.84.54.3/32"}}); got != http.StatusNoContent {
		t.Fatalf("POST host=%d", got)
	}
	if got := request(http.MethodPost, testReportToken, APIResponse{Version: 1, Networks: []string{"98.85.45.78/32"}}); got != http.StatusBadRequest {
		t.Fatalf("POST limit=%d", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
