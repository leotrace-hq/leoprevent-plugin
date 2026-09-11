package mcp

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/stats"
)

// recorder captures the query a tool call turns into.
type recorder struct {
	got  stats.Query
	body string
	err  error
}

func (r *recorder) Read(q stats.Query) ([]byte, error) {
	r.got = q
	if r.err != nil {
		return nil, r.err
	}
	body := r.body
	if body == "" {
		body = "{}"
	}
	return []byte(body), nil
}

func TestEveryToolMapsToItsView(t *testing.T) {
	// A handler that answered the wrong view would return a plausible, wrong answer — the
	// failure mode nothing downstream can detect, because every view is valid JSON.
	for name, want := range map[string]string{
		ToolStats:    "stats",
		ToolFindings: "findings",
		ToolRepos:    "repos",
		ToolRule:     "rules",
	} {
		r := &recorder{}
		if _, err := Dispatch(r)(name, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.got.View != want {
			t.Errorf("%s → view %q, want %q", name, r.got.View, want)
		}
	}
}

func TestEveryAdvertisedToolIsDispatchable(t *testing.T) {
	// The two lists are written separately, so a tool added to one and not the other would
	// appear in an agent's toolkit and fail on first use.
	for _, tool := range Tools() {
		r := &recorder{}
		if _, err := Dispatch(r)(tool.Name, nil); err != nil {
			t.Errorf("%s is advertised but not dispatchable: %v", tool.Name, err)
		}
	}
}

func TestArgumentsReachTheQuery(t *testing.T) {
	r := &recorder{}
	_, err := Dispatch(r)(ToolFindings, map[string]any{
		// A JSON number decodes as float64, which is the case that actually fires.
		"days":  float64(7),
		"limit": float64(5),
		"scope": "team",
		"repo":  "leoprevent",
		"rule":  "ssrf",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := stats.Query{View: "findings", Scope: "team", Days: 7, Repo: "leoprevent", Rule: "ssrf", Limit: 5}
	if r.got != want {
		t.Errorf("query = %+v, want %+v", r.got, want)
	}
}

func TestANumberSentAsAStringIsStillRead(t *testing.T) {
	// Models do send `"days": "30"`. The alternative to reading it is a silent fallback to the
	// default, with nothing anywhere saying the developer's "last week" was ignored.
	r := &recorder{}
	if _, err := Dispatch(r)(ToolStats, map[string]any{"days": "7"}); err != nil {
		t.Fatal(err)
	}
	if r.got.Days != 7 {
		t.Errorf("days = %d, want 7", r.got.Days)
	}
}

func TestUnparseableArgumentsFallBackToTheServerDefaults(t *testing.T) {
	// Zero is what the API reads as "use the default", so a nonsense argument costs the caller
	// nothing rather than erroring a tool call the developer cannot see the arguments of.
	r := &recorder{}
	if _, err := Dispatch(r)(ToolStats, map[string]any{"days": "a fortnight", "limit": true}); err != nil {
		t.Fatal(err)
	}
	if r.got.Days != 0 || r.got.Limit != 0 {
		t.Errorf("want both zeroed, got days=%d limit=%d", r.got.Days, r.got.Limit)
	}
}

func TestEveryToolOffersScopeAndSaysWhatTeamCosts(t *testing.T) {
	// ⚠️ THE DESCRIPTION IS THE CONTROL HERE, because the agent chooses the scope on the
	// developer's behalf and cannot ask them. A model reading a bare `["me","team"]` enum
	// picks the value that answers the broadest question — which quietly puts a colleague's
	// activity into a transcript when the developer asked about their own week.
	for _, tool := range Tools() {
		props, _ := tool.Schema["properties"].(map[string]any)
		scope, _ := props["scope"].(map[string]any)
		if scope == nil {
			t.Errorf("%s: no scope parameter", tool.Name)
			continue
		}
		desc, _ := scope["description"].(string)
		if !strings.Contains(desc, "admin") || !strings.Contains(desc, "default") {
			t.Errorf("%s: the scope description must say that team needs an admin and that me is the default, got %q",
				tool.Name, desc)
		}
	}
}

func TestNoToolAsksForAnIdentifIER(t *testing.T) {
	// ⚠️ THE PROPERTY THE WHOLE AUTHORISATION MODEL RESTS ON: the tenant and the person come
	// from the KEY, so no tool may take a parameter that names either. A tool offering a
	// `developer` or `license` argument would send an agent looking for one to fill in, and
	// the refusal would land server-side as a confusing failure rather than as a design that
	// never asked.
	banned := []string{"developer", "engineer", "email", "license", "account", "customer", "user"}
	for _, tool := range Tools() {
		props, _ := tool.Schema["properties"].(map[string]any)
		for name := range props {
			for _, bad := range banned {
				if strings.Contains(strings.ToLower(name), bad) {
					t.Errorf("%s: parameter %q names a subject; scope comes from the key alone", tool.Name, name)
				}
			}
		}
	}
}

func TestNoToolPromisesRuleContent(t *testing.T) {
	// The corpus is the moat and the client ships none of it. A description implying an agent
	// can get a rule's detection criteria from here would have the model call the tool, get a
	// title, and then fill the gap from its own priors — which is worse than not asking.
	for _, tool := range Tools() {
		lower := strings.ToLower(tool.Description)
		for _, phrase := range []string{"look_for", "does_not_apply", "rule text", "rule content", "detection criteria for"} {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s: description promises rule content (%q)", tool.Name, phrase)
			}
		}
	}
}

func TestReadFailuresSurfaceTheirMessage(t *testing.T) {
	r := &recorder{err: &stubErr{"generate a personal key in the dashboard under Plugin setup"}}
	if _, err := Dispatch(r)(ToolStats, nil); err == nil {
		t.Fatal("want the read failure to propagate")
	} else if !strings.Contains(err.Error(), "Plugin setup") {
		t.Errorf("message was rewritten: %v", err)
	}
}
