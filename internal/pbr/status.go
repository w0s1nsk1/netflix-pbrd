package pbr

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type OperationalStatus struct {
	Version      int       `json:"version"`
	Role         string    `json:"role"`
	PID          int       `json:"pid"`
	Updated      time.Time `json:"updated"`
	Desired      int       `json:"desired"`
	Learned      int       `json:"learned"`
	Applied      int       `json:"applied"`
	Reported     int       `json:"reported"`
	AppliedKnown bool      `json:"applied_known"`
	LastApply    time.Time `json:"last_apply,omitempty"`
	LastReport   time.Time `json:"last_report,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	LastErrorAt  time.Time `json:"last_error_at,omitempty"`
}

func RuntimeStatusFile(stateFile string) string {
	return stateFile + ".runtime.json"
}

func LoadOperationalStatus(path string) (OperationalStatus, error) {
	var status OperationalStatus
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return status, err
	}
	err = json.Unmarshal(b, &status)
	return status, err
}

func saveOperationalStatus(path string, status OperationalStatus) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := ioutil.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
