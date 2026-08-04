package pbr

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type APIResponse struct {
	Version  int      `json:"version"`
	Updated  string   `json:"updated"`
	Networks []string `json:"networks"`
}

type Runtime struct {
	config       Config
	interval     time.Duration
	reapplyEvery time.Duration
	runner       CommandRunner
	client       *http.Client
	syncMu       sync.Mutex
	statusMu     sync.Mutex
	mu           sync.RWMutex
	desired      []string
	learned      []string
	applied      []string
	appliedKnown bool
	appliedAt    time.Time
	reportedAt   time.Time
	lastReported []string
	lastError    string
	lastErrorAt  time.Time
	lastStatus   OperationalStatus
	statusKnown  bool
	updated      time.Time
}

func NewRuntime(c Config) (*Runtime, error) {
	return newRuntime(c, ExecRunner{})
}

func newRuntime(c Config, runner CommandRunner) (*Runtime, error) {
	interval, err := c.PollInterval()
	if err != nil {
		return nil, err
	}
	reapplyEvery, err := c.ReapplyEvery()
	if err != nil {
		return nil, err
	}
	state, err := LoadState(c.StateFile)
	if err != nil {
		return nil, err
	}
	validatedState, err := ValidateNetworks(state, false, maxNetworks(c))
	if err != nil {
		return nil, fmt.Errorf("state: %v", err)
	}
	learnedState, err := LoadState(learnedStateFile(c.StateFile))
	if err != nil {
		return nil, err
	}
	learned, err := ValidateNetworks(learnedState, true, maxNetworks(c))
	if err != nil {
		return nil, fmt.Errorf("learned state: %v", err)
	}
	desired, err := ValidateNetworks(Merge(validatedState, learned, c.SeedNetworks), false, maxNetworks(c))
	if err != nil {
		return nil, fmt.Errorf("state: %v", err)
	}
	return &Runtime{
		config:       c,
		interval:     interval,
		reapplyEvery: reapplyEvery,
		runner:       runner,
		client:       &http.Client{Timeout: 15 * time.Second},
		desired:      desired,
		learned:      learned,
		updated:      time.Now().UTC(),
	}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	r.recordStatus("")
	// Restore durable desired state before depending on DNS or the controller.
	if err := r.reconcile(ctx); err != nil {
		log.Printf("initial apply: %v", err)
		r.recordStatus(err.Error())
	}
	if r.config.DNSProxy.Listen != "" {
		if err := startDNSProxy(ctx, r.config.DNSProxy, r.learn); err != nil {
			r.recordStatus(err.Error())
			return err
		}
	}
	if r.config.API.Listen != "" {
		go r.serve(ctx)
	}
	if err := r.sync(ctx); err != nil {
		log.Printf("initial sync: %v", err)
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.sync(ctx); err != nil {
				log.Printf("sync: %v", err)
			}
		}
	}
}

func (r *Runtime) sync(ctx context.Context) (resultErr error) {
	defer func() {
		if resultErr != nil {
			r.recordStatus(resultErr.Error())
		}
	}()
	r.syncMu.Lock()
	defer r.syncMu.Unlock()

	if r.config.Role == "controller" {
		return r.reconcileLocked(ctx)
	}
	discovered, discoveryErr := r.fetch(ctx)

	if discoveryErr == nil {
		r.mu.RLock()
		previous := append([]string(nil), r.desired...)
		locallyLearned := append([]string(nil), r.learned...)
		r.mu.RUnlock()
		next, err := ValidateNetworks(Merge(discovered, locallyLearned, r.config.SeedNetworks), false, maxNetworks(r.config))
		if err != nil {
			return err
		}
		if !Equal(previous, next) {
			// Persist desired state first. Failed applies are then retried on every tick.
			if err := SaveState(r.config.StateFile, next); err != nil {
				return err
			}
			r.mu.Lock()
			r.desired = next
			r.updated = time.Now().UTC()
			r.mu.Unlock()
		}
	}

	if err := r.reconcileLocked(ctx); err != nil {
		return err
	}
	return discoveryErr
}

func (r *Runtime) learn(ctx context.Context, networks []string) (resultErr error) {
	defer func() {
		if resultErr != nil {
			r.recordStatus(resultErr.Error())
		}
	}()
	r.syncMu.Lock()
	defer r.syncMu.Unlock()

	learned, err := ValidateNetworks(networks, true, maxNetworks(r.config))
	if err != nil {
		return err
	}
	r.mu.RLock()
	previous := append([]string(nil), r.desired...)
	previousLearned := append([]string(nil), r.learned...)
	r.mu.RUnlock()
	nextLearned, err := ValidateNetworks(Merge(previousLearned, learned), true, maxNetworks(r.config))
	if err != nil {
		return err
	}
	next, err := ValidateNetworks(Merge(previous, nextLearned, r.config.SeedNetworks), false, maxNetworks(r.config))
	if err != nil {
		return err
	}
	if !Equal(previousLearned, nextLearned) {
		// Persist discoveries before applying or reporting them, so either operation
		// can be retried after a restart.
		if err := SaveState(learnedStateFile(r.config.StateFile), nextLearned); err != nil {
			return err
		}
	}
	if !Equal(previous, next) {
		if err := SaveState(r.config.StateFile, next); err != nil {
			return err
		}
		log.Printf("learned %d new Netflix addresses", len(next)-len(previous))
	}
	r.mu.Lock()
	r.desired = next
	r.learned = nextLearned
	if !Equal(previous, next) {
		r.updated = time.Now().UTC()
	}
	r.mu.Unlock()
	return r.reconcileLocked(ctx)
}

func (r *Runtime) reconcile(ctx context.Context) (resultErr error) {
	defer func() {
		if resultErr != nil {
			r.recordStatus(resultErr.Error())
		}
	}()
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	return r.reconcileLocked(ctx)
}

func (r *Runtime) reconcileLocked(ctx context.Context) error {
	r.mu.RLock()
	desired := append([]string(nil), r.desired...)
	learned := append([]string(nil), r.learned...)
	applied := append([]string(nil), r.applied...)
	appliedKnown := r.appliedKnown
	appliedAt := r.appliedAt
	lastReported := append([]string(nil), r.lastReported...)
	r.mu.RUnlock()
	changed := !appliedKnown || !Equal(desired, applied)
	periodic := !changed && time.Since(appliedAt) >= r.reapplyEvery
	if changed || periodic {
		for _, apply := range r.config.Apply {
			applyFn := applyNetworks
			if periodic {
				applyFn = reapplyNetworks
			}
			if err := applyFn(r.runner, apply, desired); err != nil {
				return fmt.Errorf("apply %s: %v", apply.Driver, err)
			}
		}
		r.mu.Lock()
		r.applied = append([]string(nil), desired...)
		r.appliedKnown = true
		r.appliedAt = time.Now()
		r.mu.Unlock()
		log.Printf("applied %d networks", len(desired))
	}

	if r.config.Role == "agent" && !Equal(learned, lastReported) {
		if err := r.report(ctx, learned); err != nil {
			return fmt.Errorf("report: %v", err)
		}
		r.mu.Lock()
		r.lastReported = append([]string(nil), learned...)
		r.reportedAt = time.Now()
		r.mu.Unlock()
	}
	r.recordStatus("")
	return nil
}

func (r *Runtime) recordStatus(lastError string) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	r.mu.Lock()
	if lastError != "" {
		r.lastError = lastError
		r.lastErrorAt = time.Now().UTC()
	}
	status := OperationalStatus{
		Version:      1,
		Role:         r.config.Role,
		PID:          os.Getpid(),
		Desired:      len(r.desired),
		Learned:      len(r.learned),
		Applied:      len(r.applied),
		Reported:     len(r.lastReported),
		AppliedKnown: r.appliedKnown,
		LastApply:    r.appliedAt,
		LastReport:   r.reportedAt,
		LastError:    r.lastError,
		LastErrorAt:  r.lastErrorAt,
	}
	r.mu.Unlock()
	previous := r.lastStatus
	previous.Updated = time.Time{}
	if r.statusKnown && previous == status {
		return
	}
	status.Updated = time.Now().UTC()
	if err := saveOperationalStatus(RuntimeStatusFile(r.config.StateFile), status); err != nil {
		log.Printf("runtime status: %v", err)
		return
	}
	r.lastStatus = status
	r.statusKnown = true
}

func learnedStateFile(stateFile string) string {
	return stateFile + ".learned"
}

func maxNetworks(c Config) int {
	if c.MaxNetworks <= 0 {
		return DefaultMaxNetworks
	}
	return c.MaxNetworks
}

func (r *Runtime) fetch(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.config.API.SourceURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.config.API.Token)
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller returned %s", resp.Status)
	}
	var payload APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Version != 1 {
		return nil, fmt.Errorf("unsupported controller response version %d", payload.Version)
	}
	return ValidateNetworks(payload.Networks, false, maxNetworks(r.config))
}

func (r *Runtime) report(ctx context.Context, networks []string) error {
	hosts := make([]string, 0, len(networks))
	for _, network := range networks {
		if strings.HasSuffix(network, "/32") {
			hosts = append(hosts, network)
		}
	}
	payload, err := json.Marshal(APIResponse{Version: 1, Networks: hosts})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.config.API.SourceURL, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.config.API.ReportToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("controller returned %s", resp.Status)
	}
	return nil
}

func (r *Runtime) httpClient() *http.Client {
	if r.client != nil {
		return r.client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (r *Runtime) acceptReport(ctx context.Context, networks []string) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	report, err := ValidateNetworks(networks, true, maxNetworks(r.config))
	if err != nil {
		return err
	}
	r.mu.RLock()
	previous := append([]string(nil), r.desired...)
	r.mu.RUnlock()
	next, err := ValidateNetworks(Merge(previous, report), false, maxNetworks(r.config))
	if err != nil {
		return err
	}
	if !Equal(previous, next) {
		if err := SaveState(r.config.StateFile, next); err != nil {
			return err
		}
		r.mu.Lock()
		r.desired = next
		r.updated = time.Now().UTC()
		r.mu.Unlock()
	}
	return r.reconcileLocked(ctx)
}

func (r *Runtime) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/networks", func(w http.ResponseWriter, req *http.Request) {
		expectedToken := r.config.API.Token
		if req.Method == http.MethodPost {
			expectedToken = r.config.API.ReportToken
		}
		provided := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expectedToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch req.Method {
		case http.MethodGet:
			r.mu.RLock()
			payload := APIResponse{Version: 1, Updated: r.updated.Format(time.RFC3339), Networks: append([]string(nil), r.desired...)}
			r.mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(payload); err != nil {
				log.Printf("api response: %v", err)
			}
		case http.MethodPost:
			if r.config.Role != "controller" {
				http.Error(w, "reports require controller role", http.StatusMethodNotAllowed)
				return
			}
			req.Body = http.MaxBytesReader(w, req.Body, 1024*1024)
			var payload APIResponse
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil || payload.Version != 1 || len(payload.Networks) > maxNetworks(r.config) {
				http.Error(w, "invalid report", http.StatusBadRequest)
				return
			}
			if _, err := ValidateNetworks(payload.Networks, true, maxNetworks(r.config)); err != nil {
				http.Error(w, "invalid report", http.StatusBadRequest)
				return
			}
			r.mu.RLock()
			current := append([]string(nil), r.desired...)
			r.mu.RUnlock()
			if _, err := ValidateNetworks(Merge(current, payload.Networks), false, maxNetworks(r.config)); err != nil {
				http.Error(w, "invalid report", http.StatusBadRequest)
				return
			}
			if err := r.acceptReport(req.Context(), payload.Networks); err != nil {
				log.Printf("agent report: %v", err)
				http.Error(w, "report apply failed", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return mux
}

func (r *Runtime) serve(ctx context.Context) {
	server := &http.Server{Addr: r.config.API.Listen, Handler: r.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	var err error
	if r.config.API.TLSCert != "" {
		err = server.ListenAndServeTLS(r.config.API.TLSCert, r.config.API.TLSKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Printf("api server: %v", err)
	}
}
