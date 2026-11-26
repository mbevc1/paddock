package web

import (
	"net/http"
	"strconv"

	"github.com/mbevc1/paddock/internal/agent/ops"
)

// LogChoice is one log the logs page offers, keyed by the name the agent takes.
type LogChoice struct {
	Name, Label string
}

var logChoices = []LogChoice{
	{"error", "Apache errors"},
	{"access", "Access"},
	{"php", "PHP errors"},
	{"fpm", "PHP-FPM"},
}

var logLineChoices = []int{100, 200, 500, 1000}

// LogsData is what the logs page shows.
type LogsData struct {
	Vhost   ops.VhostDetail
	Log     string
	Lines   int
	Choices []LogChoice
	Counts  []int
	Entries ops.VhostLog
}

func (s *Server) vhostLogsPage(w http.ResponseWriter, r *http.Request) {
	d := LogsData{Log: logChoices[0].Name, Lines: 200, Choices: logChoices, Counts: logLineChoices}
	for _, c := range logChoices {
		if c.Name == r.URL.Query().Get("log") {
			d.Log = c.Name
		}
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("lines")); err == nil {
		for _, c := range logLineChoices {
			if n == c {
				d.Lines = n
			}
		}
	}
	if err := s.agentCall(r, "vhost.get", ops.VhostIDArgs{VhostID: r.PathValue("id")}, &d.Vhost); err != nil {
		s.agentFailed(w, r, "/vhosts", err)
		return
	}
	args := ops.VhostLogArgs{VhostID: d.Vhost.ID, Log: d.Log, Lines: d.Lines}
	if err := s.agentCall(r, "vhost.log.tail", args, &d.Entries); err != nil {
		s.agentFailed(w, r, vhostPath(r), err)
		return
	}
	s.render(w, r, http.StatusOK, "logs.html", Page{Title: "Logs · " + d.Vhost.Primary, Data: d})
}
