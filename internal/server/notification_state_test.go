package server

import (
	"testing"
	"time"
)

func TestNotificationHealthRecoveryPairing(t *testing.T) {
	now := time.Now()
	for _, initial := range []notificationFailure{{}, {Since: now}, {Since: now, Sent: true}} {
		state, down, recovered := advanceNotificationHealth(initial, false, false, now)
		if down || recovered || state.Sent != initial.Sent {
			t.Fatal("unknown status changed reported outage or emitted an event")
		}
		state, down, recovered = advanceNotificationHealth(state, false, true, now)
		if down || recovered != initial.Sent || state.Sent || !state.Since.IsZero() {
			t.Fatal("explicit recovery was not paired with a reported outage")
		}
		_, down, recovered = advanceNotificationHealth(state, false, true, now)
		if down || recovered {
			t.Fatal("duplicate or first-ever recovery")
		}
	}
}

func TestNotificationFailureThresholdAndRecovery(t *testing.T) {
	start := time.Now()
	state, emit := advanceNotificationFailure(notificationFailure{}, true, start)
	if emit {
		t.Fatal("initial failure emitted")
	}
	state, emit = advanceNotificationFailure(state, true, start.Add(time.Minute))
	if emit {
		t.Fatal("failure emitted before more than one minute")
	}
	state, emit = advanceNotificationFailure(state, true, start.Add(61*time.Second))
	if !emit {
		t.Fatal("sustained failure did not emit")
	}
	state, emit = advanceNotificationFailure(state, true, start.Add(2*time.Minute))
	if emit {
		t.Fatal("duplicate failure emitted")
	}
	state, emit = advanceNotificationFailure(state, false, start.Add(3*time.Minute))
	if emit || !state.Since.IsZero() {
		t.Fatal("recovery did not reset")
	}
	state, _ = advanceNotificationFailure(state, true, start.Add(4*time.Minute))
	_, emit = advanceNotificationFailure(state, true, start.Add(5*time.Minute+time.Second))
	if !emit {
		t.Fatal("new outage did not emit")
	}
}
