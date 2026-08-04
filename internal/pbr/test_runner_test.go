package pbr

import (
	"fmt"
	"strings"
)

type runnerCall struct {
	name  string
	args  []string
	input string
}

type fakeRunner struct {
	calls    []runnerCall
	outputs  map[string]string
	failures map[string]int
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: make(map[string]string), failures: make(map[string]int)}
}

func commandKey(name string, args ...string) string {
	return name + " " + strings.Join(args, " ")
}

func (f *fakeRunner) record(input, name string, args ...string) error {
	f.calls = append(f.calls, runnerCall{name: name, args: append([]string(nil), args...), input: input})
	key := commandKey(name, args...)
	if f.failures[key] > 0 {
		f.failures[key]--
		return fmt.Errorf("injected failure: %s", key)
	}
	return nil
}

func (f *fakeRunner) Run(name string, args ...string) error {
	return f.record("", name, args...)
}

func (f *fakeRunner) RunInput(input, name string, args ...string) error {
	return f.record(input, name, args...)
}

func (f *fakeRunner) Output(name string, args ...string) ([]byte, error) {
	if err := f.record("", name, args...); err != nil {
		return nil, err
	}
	return []byte(f.outputs[commandKey(name, args...)]), nil
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	return "/sbin/" + name, nil
}

func (f *fakeRunner) Exists(string) bool { return false }

func (f *fakeRunner) inputs() string {
	var values []string
	for _, call := range f.calls {
		if call.input != "" {
			values = append(values, call.input)
		}
	}
	return strings.Join(values, "\n")
}

func (f *fakeRunner) commandLines() string {
	var values []string
	for _, call := range f.calls {
		values = append(values, commandKey(call.name, call.args...))
	}
	return strings.Join(values, "\n")
}
