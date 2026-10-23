package process

import (
	"os"
	"testing"
	"time"

	"github.com/pbadevel/Uplert/internal/model"
)

func TestPolicyDecide(t *testing.T) {
	cases := []struct {
		name      string
		enabled   bool
		dryRun    bool
		onlyCrit  bool
		level     model.Level
		wantAlert bool
		wantAct   Action
	}{
		{
			name:      "disabled always none",
			enabled:   false,
			onlyCrit:  true,
			level:     model.LevelCritical,
			wantAlert: true,
			wantAct:   ActionNone,
		},
		{
			name:      "enabled critical kill",
			enabled:   true,
			onlyCrit:  true,
			level:     model.LevelCritical,
			wantAlert: true,
			wantAct:   ActionKill,
		},
		{
			name:      "enabled high none due kill_only_critical",
			enabled:   true,
			onlyCrit:  true,
			level:     model.LevelHigh,
			wantAlert: true,
			wantAct:   ActionNone,
		},
		{
			name:      "enabled high kill when not restricted",
			enabled:   true,
			onlyCrit:  false,
			level:     model.LevelHigh,
			wantAlert: true,
			wantAct:   ActionKill,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &Policy{
				Enabled:          c.enabled,
				DryRun:           c.dryRun,
				KillOnlyCritical: c.onlyCrit,
			}

			gotAlert, gotAct := p.Decide(model.Finding{
				Level: c.level,
				Time:  time.Now(),
			})

			if gotAlert != c.wantAlert || gotAct != c.wantAct {
				t.Errorf("Decide() = (%v, %v), want (%v, %v)",
					gotAlert, gotAct, c.wantAlert, c.wantAct)
			}
		})
	}
}

func TestKillProcessRefusesSelf(t *testing.T) {
	if err := KillProcess(int32(os.Getpid())); err == nil {
		t.Fatal("must refuse to kill own pid")
	}

	if err := KillProcess(1); err == nil {
		t.Fatal("must refuse to kill pid 1")
	}
}
