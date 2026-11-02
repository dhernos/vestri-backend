package server

import "time"

type notificationFailure struct {
	Since time.Time
	Sent  bool
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
