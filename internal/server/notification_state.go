package server

import "time"

type notificationFailure struct {
	Since time.Time
	Sent  bool
}

func advanceNotificationHealth(previous notificationFailure, unhealthy, healthy bool, now time.Time) (notificationFailure, bool, bool) {
	if healthy {
		return notificationFailure{}, false, previous.Sent
	}
	if !unhealthy {
		if previous.Sent {
			return previous, false, false
		}
		return notificationFailure{}, false, false
	}
	next, emit := advanceNotificationFailure(previous, true, now)
	return next, emit, false
}

func advanceNotificationFailure(previous notificationFailure, unhealthy bool, now time.Time) (notificationFailure, bool) {
	if !unhealthy {
		return notificationFailure{}, false
	}
	if previous.Since.IsZero() {
		return notificationFailure{Since: now}, false
	}
	if !previous.Sent && now.Sub(previous.Since) > time.Minute {
		previous.Sent = true
		return previous, true
	}
	return previous, false
}
