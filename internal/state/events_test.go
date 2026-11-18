package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEvents(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	for _, e := range []Event{
		{Kind: EventApplyFailed, OwnerID: 3, Message: "vhost.create failed"},
		{Kind: EventCertExpiring, OwnerID: 3, VhostN: 12, Message: "expires soon"},
		{Kind: EventQuotaWarning, OwnerID: 4, Message: "90%"},
	} {
		if _, err := s.AppendEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ListEvents(ctx, 0, 10)
	if err != nil || len(all) != 3 || all[0].Kind != EventApplyFailed || all[1].VhostN != 12 || !all[0].Time.Equal(now) {
		t.Fatalf("ListEvents = %+v, %v", all, err)
	}
	if after, _ := s.ListEvents(ctx, all[1].ID, 10); len(after) != 1 || after[0].Kind != EventQuotaWarning {
		t.Errorf("events after cursor = %+v", after)
	}
	if ok, err := s.EventSince(ctx, EventCertExpiring, 12, now.Add(-time.Hour)); !ok || err != nil {
		t.Errorf("EventSince = %v, %v", ok, err)
	}
	if ok, _ := s.EventSince(ctx, EventCertExpiring, 12, now.Add(time.Hour)); ok {
		t.Error("EventSince found a future event")
	}
	if ok, _ := s.EventSince(ctx, EventCertExpiring, 13, now.Add(-time.Hour)); ok {
		t.Error("EventSince matched another vhost")
	}

	o, err := s.CreateOwner(ctx, "acme", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if q, err := s.GetQuotaState(ctx, o.ID); err != nil || q.Warned || q.Enforced {
		t.Errorf("initial quota state = %+v, %v", q, err)
	}
	if err := s.SetQuotaState(ctx, o.ID, QuotaState{Warned: true, Enforced: true}); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.GetQuotaState(ctx, o.ID); !q.Warned || !q.Enforced {
		t.Errorf("quota state = %+v", q)
	}

	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	v, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", []string{"b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.VhostByDomain(ctx, "b.example.com"); err != nil || got.N != v.N {
		t.Errorf("VhostByDomain = %+v, %v", got, err)
	}
	if _, err := s.VhostByDomain(ctx, "c.example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown domain: %v", err)
	}
}
