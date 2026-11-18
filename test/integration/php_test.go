//go:build integration

package integration

import (
	"os"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
)

func TestPHPVersionInstall(t *testing.T) {
	h := newAgent(t)
	const unit = "/etc/systemd/system/paddock-php84-fpm@.service"
	_, err := os.Stat(unit)
	hadUnit := err == nil

	h.installPHP(t, "8.4")
	if _, err := os.Stat("/opt/remi/php84/root/usr/sbin/php-fpm"); err != nil {
		t.Errorf("php-fpm missing: %v", err)
	}
	if _, err := os.Stat(unit); err != nil {
		t.Errorf("unit missing: %v", err)
	}
	if hadUnit {
		t.Log("PHP 8.4 was present before the test; leaving it installed")
		return
	}
	h.mustJob(t, "php.version.remove", ops.PHPVersionArgs{Version: "8.4"}, 15*time.Minute)
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Errorf("unit left after removal: %v", err)
	}
}
