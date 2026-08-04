package pbr

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type InstallLayout struct {
	Platform string
	Binary   string
	Config   string
	Service  string
}

func DetectInstallLayout() InstallLayout {
	if pathExists("/etc/openwrt_release") {
		return InstallLayout{Platform: "openwrt", Binary: "/usr/sbin/netflix-pbrd", Config: "/etc/netflix-pbrd.json", Service: "/etc/init.d/netflix-pbrd"}
	}
	if pathExists("/opt/etc/init.d") {
		return InstallLayout{Platform: "entware", Binary: "/opt/sbin/netflix-pbrd", Config: "/opt/etc/netflix-pbrd.json", Service: "/opt/etc/init.d/S48netflix-pbrd"}
	}
	return InstallLayout{Platform: "systemd", Binary: "/usr/local/sbin/netflix-pbrd", Config: "/etc/netflix-pbrd.json", Service: "/etc/systemd/system/netflix-pbrd.service"}
}

func InstallSelf(configPath string, runner CommandRunner) (InstallLayout, error) {
	layout := DetectInstallLayout()
	if os.Geteuid() != 0 {
		return layout, fmt.Errorf("install must run as root")
	}
	if _, err := LoadConfig(configPath); err != nil {
		return layout, fmt.Errorf("config: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return layout, err
	}
	if err := installFile(executable, layout.Binary, 0755); err != nil {
		return layout, err
	}
	if err := installFile(configPath, layout.Config, 0600); err != nil {
		return layout, err
	}
	if err := writeService(layout); err != nil {
		return layout, err
	}
	if err := enableService(layout, runner); err != nil {
		return layout, err
	}
	return layout, nil
}

func installFile(source, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	if pathExists(target) {
		backup := target + ".bak." + time.Now().UTC().Format("20060102T150405Z")
		if err := copyFile(target, backup, mode); err != nil {
			return err
		}
	}
	tmp := target + ".new"
	if err := copyFile(source, tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

func copyFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(target, mode)
}

func writeService(layout InstallLayout) error {
	var body string
	switch layout.Platform {
	case "entware":
		body = "#!/bin/sh\nPIDFILE=/opt/var/run/netflix-pbrd.pid\ncase \"$1\" in\nstart) /bin/start-stop-daemon -S -b -m -p \"$PIDFILE\" -x " + layout.Binary + " -- -config " + layout.Config + ";;\nstop) /bin/start-stop-daemon -K -p \"$PIDFILE\" || true; rm -f \"$PIDFILE\";;\nrestart) $0 stop; $0 start;;\nesac\n"
	case "openwrt":
		body = "#!/bin/sh /etc/rc.common\nSTART=95\nUSE_PROCD=1\nstart_service() {\n  procd_open_instance\n  procd_set_param command " + layout.Binary + " -config " + layout.Config + "\n  procd_set_param respawn 3600 5 5\n  procd_set_param stdout 1\n  procd_set_param stderr 1\n  procd_close_instance\n}\n"
	default:
		body = "[Unit]\nDescription=Netflix policy routing daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=" + layout.Binary + " -config " + layout.Config + "\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=true\n\n[Install]\nWantedBy=multi-user.target\n"
	}
	return installBytes([]byte(body), layout.Service, 0755)
}

func installBytes(content []byte, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	if pathExists(target) {
		backup := target + ".bak." + time.Now().UTC().Format("20060102T150405Z")
		if err := copyFile(target, backup, mode); err != nil {
			return err
		}
	}
	tmp := target + ".new"
	if err := ioutil.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

func enableService(layout InstallLayout, runner CommandRunner) error {
	switch layout.Platform {
	case "systemd":
		if err := runner.Run("systemctl", "daemon-reload"); err != nil {
			return err
		}
		return runner.Run("systemctl", "enable", "--now", "netflix-pbrd")
	case "openwrt":
		if err := runner.Run(layout.Service, "enable"); err != nil {
			return err
		}
		return runner.Run(layout.Service, "restart")
	default:
		return runner.Run(layout.Service, "restart")
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
