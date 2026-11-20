package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func executablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

// restartInstalledService is used only by the interactive updater for the
// standard Linux systemd installation. In-process client updates have their
// own reconnect protocol and do not call systemctl.
func restartInstalledService(ctx context.Context, component, path string) error {
	unit := component + ".service"
	restart := func(ctx context.Context) error {
		out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput()
		if err != nil {
			return fmt.Errorf("restart %s: %w: %s", unit, err, out)
		}
		return nil
	}

	healthCtx, cancelHealth := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelHealth()
	check := func() error {
		if err := restart(healthCtx); err != nil {
			return err
		}
		var pid string
		for range 6 {
			timer := time.NewTimer(time.Second)
			select {
			case <-timer.C:
			case <-healthCtx.Done():
				timer.Stop()
				return healthCtx.Err()
			}
			out, err := exec.CommandContext(healthCtx, "systemctl", "show",
				"--property=ActiveState,MainPID,NRestarts", unit).Output()
			if err != nil {
				return err
			}
			fields := make(map[string]string)
			for _, line := range strings.Split(string(out), "\n") {
				if key, value, found := strings.Cut(line, "="); found {
					fields[key] = value
				}
			}
			current := fields["MainPID"]
			if fields["ActiveState"] != "active" || fields["NRestarts"] != "0" ||
				current == "" || current == "0" || (pid != "" && pid != current) {
				return fmt.Errorf("%s did not remain healthy after update", unit)
			}
			pid = current
		}
		return nil
	}
	if err := check(); err != nil {
		if rollbackErr := RestorePrevious(path); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("restore previous executable: %w", rollbackErr))
		}
		rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancelRollback()
		if restartErr := restart(rollbackCtx); restartErr != nil {
			return errors.Join(err, restartErr)
		}
		return fmt.Errorf("previous executable restored: %w", err)
	}
	return nil
}
