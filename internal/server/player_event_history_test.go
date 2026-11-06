package server

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestPlayerEventHistoryUsesCompletionTime(t *testing.T) {
	events := make([]json.RawMessage, maxPlayerEventHistory+1)
	for index := range events {
		completed := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC).Add(time.Duration(index) * time.Second)
		events[index] = json.RawMessage(fmt.Sprintf(`{"id":"%04d","time":"2026-01-01T00:00:00Z","completedAt":%q}`, len(events)-index, completed.Format(time.RFC3339Nano)))
	}
	retained := boundedPlayerEventHistory(events)
	if len(retained) != maxPlayerEventHistory || string(retained[0]) != string(events[len(events)-1]) || string(retained[len(retained)-1]) != string(events[1]) {
		t.Fatal("completion time must take priority over login start time and ID")
	}
	if boundedPlayerEventHistory(nil) != nil {
		t.Fatal("empty history changed")
	}
}

func TestPlayerEventHistoryBoundAndOrdering(t *testing.T) {
	events := make([]json.RawMessage, 0, maxPlayerEventHistory+2)
	events = append(events, json.RawMessage(`{"id":"invalid","time":"unknown"}`))
	for index := 0; index <= maxPlayerEventHistory; index++ {
		events = append(events, json.RawMessage(fmt.Sprintf(`{"id":"%04d","time":"2026-11-06T12:00:00Z"}`, index)))
	}
	retained := boundedPlayerEventHistory(events)
	if len(retained) != maxPlayerEventHistory {
		t.Fatalf("retained %d events", len(retained))
	}
	if string(retained[0]) != string(events[len(events)-1]) || string(retained[len(retained)-1]) != string(events[2]) {
		t.Fatal("did not evict oldest events with deterministic ID tie-break")
	}
	if string(events[0]) != `{"id":"invalid","time":"unknown"}` {
		t.Fatal("mutated source history")
	}
}
