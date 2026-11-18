package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/web/store"
)

const (
	eventsCursorKey  = "events.cursor"
	eventsPageSize   = 100
	sseKeepAlive     = 25 * time.Second
	notificationsMax = 50
)

// hub fans new notifications out to each user's open event streams.
type hub struct {
	mu   sync.Mutex
	subs map[int64]map[chan store.Notification]struct{}
}

func newHub() *hub { return &hub{subs: map[int64]map[chan store.Notification]struct{}{}} }

func (h *hub) subscribe(userID int64) chan store.Notification {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan store.Notification, 16)
	if h.subs[userID] == nil {
		h.subs[userID] = map[chan store.Notification]struct{}{}
	}
	h.subs[userID][ch] = struct{}{}
	return ch
}

func (h *hub) unsubscribe(userID int64, ch chan store.Notification) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[userID][ch]; ok {
		delete(h.subs[userID], ch)
		close(ch)
	}
}

// publish delivers without blocking: a stream too slow to keep up misses the live update and
// still finds the notification on its next page load.
func (h *hub) publish(n store.Notification) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[n.UserID] {
		select {
		case ch <- n:
		default:
		}
	}
}

func (h *hub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for user, chans := range h.subs {
		for ch := range chans {
			close(ch)
		}
		delete(h.subs, user)
	}
}

// notifyUser stores a notification and pushes it to the user's open pages.
func (s *Server) notifyUser(ctx context.Context, userID int64, kind, message string) {
	id, err := s.store.AddNotification(ctx, userID, kind, message)
	if err != nil {
		s.log.Error("notification failed", "err", err)
		return
	}
	s.hub.publish(store.Notification{ID: id, UserID: userID, Kind: kind, Message: message, CreatedAt: s.now()})
}

// recipients returns who hears about an event: the users of its owner, and admins when the
// event concerns no owner or an apply failed.
func (s *Server) recipients(ctx context.Context, e state.Event) ([]int64, error) {
	var ids []int64
	if e.OwnerID != 0 {
		users, err := s.store.ListUsers(ctx, e.OwnerID)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			ids = append(ids, u.ID)
		}
	}
	if e.OwnerID == 0 || e.Kind == state.EventApplyFailed {
		all, err := s.store.ListUsers(ctx, 0)
		if err != nil {
			return nil, err
		}
		for _, u := range all {
			if u.Role == store.RoleAdmin {
				ids = append(ids, u.ID)
			}
		}
	}
	return ids, nil
}

// PollEvents turns agent events into notifications until ctx ends. The cursor is stored, so a
// restart neither repeats nor drops events.
func (s *Server) PollEvents(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := s.pollOnce(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("polling agent events failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) pollOnce(ctx context.Context) error {
	raw, err := s.store.Meta(ctx, eventsCursorKey)
	if err != nil {
		return err
	}
	cursor, _ := strconv.ParseInt(raw, 10, 64)
	for {
		var page ops.EventsPage
		if err := s.agent.Call(ctx, "events.list", nil, "", ops.EventsListArgs{Since: cursor, Limit: eventsPageSize}, &page); err != nil {
			return err
		}
		for _, e := range page.Events {
			ids, err := s.recipients(ctx, e)
			if err != nil {
				return err
			}
			for _, id := range ids {
				s.notifyUser(ctx, id, string(e.Kind), e.Message)
			}
		}
		if page.Next == cursor {
			return nil
		}
		cursor = page.Next
		if err := s.store.SetMeta(ctx, eventsCursorKey, strconv.FormatInt(cursor, 10)); err != nil {
			return err
		}
		if len(page.Events) < eventsPageSize {
			return nil
		}
	}
}

func (s *Server) notificationRoutes(rt *Router) {
	rt.Handle(Route{Method: "GET", Pattern: "/notifications", Perm: PermSelf, Handler: s.notificationsPage})
	rt.Handle(Route{Method: "GET", Pattern: "/notifications/stream", Perm: PermSelf, Handler: s.notificationStream})
	rt.Handle(Route{Method: "POST", Pattern: "/notifications/read", Perm: PermSelf, Handler: s.markRead})
}

func (s *Server) notificationsPage(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.RecentNotifications(r.Context(), identityFrom(r).User.ID, notificationsMax)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "notifications.html", Page{Title: "Notifications", Data: list})
}

func (s *Server) markRead(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err := s.store.MarkNotificationsRead(r.Context(), identityFrom(r).User.ID, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

type streamEvent struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Time    string `json:"time"`
}

// notificationStream sends the user's new notifications as Server-Sent Events.
func (s *Server) notificationStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	userID := identityFrom(r).User.ID
	ch := s.hub.subscribe(userID)
	defer s.hub.unsubscribe(userID, ch)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	keep := time.NewTicker(sseKeepAlive)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
		case n, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(streamEvent{ID: n.ID, Kind: n.Kind, Message: n.Message, Time: n.CreatedAt.UTC().Format(time.RFC3339)})
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: notification\ndata: %s\n\n", n.ID, data); err != nil {
				return
			}
		}
		flusher.Flush()
	}
}
