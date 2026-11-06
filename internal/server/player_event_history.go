package server

import (
	"encoding/json"
	"sort"
	"time"
)

const maxPlayerEventHistory = 1000

func boundedPlayerEventHistory(events []json.RawMessage) []json.RawMessage {
	if len(events) <= maxPlayerEventHistory {
		return events
	}
	type eventEntry struct {
		content json.RawMessage
		when    time.Time
		id      string
	}
	entries := make([]eventEntry, 0, len(events))
	for _, event := range events {
		var fields struct {
			ID          string `json:"id"`
			Time        string `json:"time"`
			CompletedAt string `json:"completedAt"`
		}
		_ = json.Unmarshal(event, &fields)
		when, err := time.Parse(time.RFC3339Nano, fields.CompletedAt)
		if err != nil {
			when, _ = time.Parse(time.RFC3339Nano, fields.Time)
		}
		entries = append(entries, eventEntry{content: event, when: when, id: fields.ID})
	}
	sort.SliceStable(entries, func(left, right int) bool {
		if entries[left].when.Equal(entries[right].when) {
			return entries[left].id > entries[right].id
		}
		return entries[left].when.After(entries[right].when)
	})
	retained := make([]json.RawMessage, 0, maxPlayerEventHistory)
	for _, entry := range entries[:maxPlayerEventHistory] {
		retained = append(retained, entry.content)
	}
	return retained
}
