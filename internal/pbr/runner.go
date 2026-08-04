package pbr

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type CommandRunner interface {
	Run(name string, args ...string) error
	RunInput(input, name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
	LookPath(name string) (string, error)
	Exists(path string) bool
}

type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) error {
	_, err := (ExecRunner{}).Output(name, args...)
	return err
}

func (ExecRunner) RunInput(input, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return commandError(name, args, err, out)
	}
	return nil
}

func (ExecRunner) Output(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, commandError(name, args, err, out)
	}
	return out, nil
}

func (ExecRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (ExecRunner) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func commandError(name string, args []string, err error, out []byte) error {
	return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
}
