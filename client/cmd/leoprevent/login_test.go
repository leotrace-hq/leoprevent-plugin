package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

func TestLoginFallbackPersistsOnlyValidatedCredential(
	t *testing.T,
) {
	t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
	t.Setenv(config.EnvLicenseKey, "lp_live_override")
	var server *httptest.Server
	key := "lp_live_secret_test_key"
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/validate" {
			if r.Header.Get("Authorization") != "Bearer "+key {
				t.Error("missing credential")
			}
			json.NewEncoder(w).Encode(loginResponse{LicenseID: "lic_test", AccountID: "acct_test"})
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["action"] == "start" {
			json.NewEncoder(w).Encode(loginResponse{DeviceCode: strings.Repeat("a", 43), UserCode: "0123456789ABCDEF", VerificationURI: server.URL + "/device?code=0123456789ABCDEF", ExpiresIn: 60, Interval: 1})
		} else {
			if body["device_code"] != strings.Repeat("a", 43) {
				t.Error("exchange binding missing")
			}
			json.NewEncoder(w).Encode(loginResponse{Key: key, LicenseID: "lic_test", AccountID: "acct_test", DeviceID: "device"})
		}
	}))
	defer server.Close()
	var output bytes.Buffer
	err := performLogin(context.Background(), &config.Config{ServerURL: server.URL, DashboardURL: server.URL, Tier: "cloud"}, server.Client(), false, "", &output, func(string) error { return errors.New("no browser") })
	if err != nil {
		t.Fatal(err)
	}
	if config.UserLicenseKey() != key {
		t.Fatal("credential not saved")
	}
	if strings.Contains(output.String(), key) || strings.Contains(output.String(), strings.Repeat("a", 43)) {
		t.Fatal("secret in terminal output")
	}
	for _, expected := range []string{"Could not open a browser", "LEOPREVENT_LICENSE_KEY overrides"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("missing %s", expected)
		}
	}
}

func TestLoginCancellationPreservesExistingCredential(
	t *testing.T,
) {
	t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
	path, err := config.SaveLicense("lp_live_old")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	err = performLogin(ctx, &config.Config{ServerURL: server.URL, DashboardURL: server.URL, Tier: "cloud"}, server.Client(), true, "", &bytes.Buffer{}, func(string) error { t.Fatal("browser opened"); return nil })
	if err == nil {
		t.Fatal("expected failure")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("working credential changed")
	}
}

func TestLoginRejectsUnsafeOrigins(
	t *testing.T,
) {
	for _, address := range []string{"http://remote.example", "https://user:secret@example.com", "https://example.com/path", "https://example.com?key=secret", "https://example.com#secret", "file:///tmp/key"} {
		if _, err := loginURL(address); err == nil {
			t.Errorf("accepted unsafe origin %s", address)
		}
	}
}

func TestBrowserLoginLive(
	t *testing.T,
) {
	if os.Getenv("LEO234_BROWSER_LOGIN") != "1" {
		t.Skip("set LEO234_BROWSER_LOGIN=1 with isolated local services")
	}
	t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.ServerURL, "http://127.0.0.1:") || !strings.HasPrefix(cfg.DashboardURL, "http://127.0.0.1:") {
		t.Fatal("live test requires loopback services")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	err = performLogin(ctx, cfg, client, os.Getenv("LEO234_BROWSER_AUTO") != "1", "", os.Stdout, openLoginBrowser)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load()
	if err != nil || loaded.LicenseKey == "" {
		t.Fatal("normal hook credential loader did not load login")
	}
	_, status, err := loginRequest(ctx, client, cfg.ServerURL+"/auth/validate", nil, loaded.LicenseKey)
	if err != nil || status != http.StatusOK {
		t.Fatal("normal hook credential failed authentication")
	}
}

func TestFailedLoginAfterAuthorizationKeepsExistingKey(
	t *testing.T,
) {
	for _, failure := range []string{"access_denied", "expired_token", "invalid_credential"} {
		t.Run(failure, func(t *testing.T) {
			t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
			path, err := config.SaveLicense("lp_live_working")
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/auth/validate" {
					cancel()
					w.WriteHeader(403)
					json.NewEncoder(w).Encode(loginResponse{})
					return
				}
				var input map[string]string
				json.NewDecoder(r.Body).Decode(&input)
				if input["action"] == "start" {
					json.NewEncoder(w).Encode(loginResponse{DeviceCode: strings.Repeat("b", 43), UserCode: "ABCDEF0123456789", VerificationURI: server.URL + "/device?code=ABCDEF0123456789", ExpiresIn: 60, Interval: 1})
					return
				}
				if failure == "invalid_credential" {
					json.NewEncoder(w).Encode(loginResponse{Key: "lp_live_unverified", LicenseID: "lic", AccountID: "acct", DeviceID: "dev"})
					return
				}
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(loginResponse{Error: failure})
			}))
			defer server.Close()
			err = performLogin(ctx, &config.Config{ServerURL: server.URL, DashboardURL: server.URL, Tier: "cloud"}, server.Client(), true, "", &bytes.Buffer{}, func(string) error { return nil })
			if err == nil {
				t.Fatal("expected failure")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("failed login changed the working credential")
			}
		})
	}
}

func TestLoginReturnApp(t *testing.T) {
	for _, tc := range []struct {
		name, platform, entrypoint, terminal, ssh, executable, want string
		headless                                                    bool
	}{
		{name: "Claude desktop", platform: "darwin", entrypoint: "claude-desktop", terminal: "Apple_Terminal", want: "com.anthropic.claudefordesktop"},
		{name: "Codex desktop", platform: "darwin", executable: "/Applications/Codex.app/Contents/MacOS/Codex", terminal: "Apple_Terminal", want: "com.openai.codex"},
		{name: "Codex current app", platform: "darwin", executable: "/Applications/ChatGPT.app/Contents/Resources/codex", want: "com.openai.codex"},
		{name: "Copilot VS Code", platform: "darwin", executable: "/Applications/Visual Studio Code.app/Contents/MacOS/Electron", want: "com.microsoft.VSCode"},
		{name: "Claude terminal", platform: "darwin", terminal: "Apple_Terminal", want: "com.apple.Terminal"},
		{name: "Codex terminal", platform: "darwin", terminal: "iTerm.app", want: "com.googlecode.iterm2"},
		{name: "Copilot terminal", platform: "darwin", executable: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", want: "com.apple.Terminal"},
		{name: "remote desktop", platform: "darwin", entrypoint: "remote_desktop", terminal: "Apple_Terminal"},
		{name: "SSH", platform: "darwin", ssh: "remote", entrypoint: "claude-desktop"},
		{name: "headless", platform: "darwin", entrypoint: "claude-desktop", headless: true},
		{name: "unknown", platform: "darwin", terminal: "unknown"},
		{name: "Windows", platform: "windows", entrypoint: "claude-desktop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"CLAUDE_CODE_ENTRYPOINT": tc.entrypoint, "TERM_PROGRAM": tc.terminal, "SSH_CONNECTION": tc.ssh}
			got := loginReturnApp(tc.headless, tc.platform, func(k string) string { return env[k] }, 42, func(int) (int, string) { return 1, tc.executable })
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoginCompletion(t *testing.T) {
	for _, app := range []string{"", "com.apple.Terminal", "com.anthropic.claudefordesktop"} {
		var output bytes.Buffer
		calls := 0
		finishLogin(app, &output, func(got string) error {
			calls++
			if got != app {
				t.Fatal("wrong app")
			}
			if output.Len() != 0 {
				t.Fatal("success printed before app return")
			}
			return nil
		})
		if output.String() != "> 🛡️ **LeoPrevent** · Connected\n" {
			t.Fatalf("unexpected output: %s", &output)
		}
		if (app == "" && calls != 0) || (app != "" && calls != 1) {
			t.Fatal("unexpected activation")
		}
	}
	var output bytes.Buffer
	finishLogin("com.apple.Terminal", &output, func(string) error { return errors.New("unavailable") })
	if !strings.Contains(output.String(), "Switch back") || !strings.Contains(output.String(), "LeoPrevent** · Connected") {
		t.Fatal(output.String())
	}
}

func startLoginAgainst(
	t *testing.T,
	agentName string,
	verificationQuery func(code string) string,
) (map[string]string, string, error) {
	t.Helper()
	t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
	var started map[string]string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/validate" {
			json.NewEncoder(w).Encode(loginResponse{LicenseID: "lic_test", AccountID: "acct_test"})
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["action"] == "start" {
			started = body
			json.NewEncoder(w).Encode(loginResponse{DeviceCode: strings.Repeat("a", 43), UserCode: "A3F907C21B8E4D61", VerificationURI: server.URL + "/device?" + verificationQuery("A3F907C21B8E4D61"), ExpiresIn: 60, Interval: 1})
			return
		}
		json.NewEncoder(w).Encode(loginResponse{Key: "lp_live_k", LicenseID: "lic_test", AccountID: "acct_test", DeviceID: "device"})
	}))
	defer server.Close()
	var output bytes.Buffer
	err := performLogin(context.Background(), &config.Config{ServerURL: server.URL, DashboardURL: server.URL, Tier: "cloud"}, server.Client(), true, agentName, &output, func(string) error { return nil })
	return started, output.String(), err
}

func TestLoginStartReportsAgentFromTheClosedSet(
	t *testing.T,
) {
	for _, tc := range []struct{ name, agent, want string }{
		{"known agent", "codex", "codex"},
		{"unknown agent omitted", "", ""},
		{"invalid agent dropped", "cursor", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			body, _, err := startLoginAgainst(t, tc.agent, func(code string) string { return "code=" + code })

			// Assert
			if err != nil {
				t.Fatal(err)
			}
			got, present := body["agent"]
			if tc.want == "" && present {
				t.Fatalf("agent field must be omitted, got %q", got)
			}
			if got != tc.want {
				t.Fatalf("agent = %q, want %q", got, tc.want)
			}
			if _, asked := body["link"]; asked {
				t.Fatalf("link must not be sent: the page no longer asks for the last 4")
			}
		})
	}
}

func TestLoginAcceptsOnlyTheFullCodeURL(
	t *testing.T,
) {
	for _, tc := range []struct {
		name  string
		query func(string) string
		ok    bool
	}{
		{"full code", func(c string) string { return "code=" + c }, true},
		{"prefix link", func(c string) string { return "code=" + c[:12] }, false},
		{"shorter prefix", func(c string) string { return "code=" + c[:8] }, false},
		{"other code", func(string) string { return "code=0123456789AB" }, false},
		{"extra parameter", func(c string) string { return "code=" + c + "&x=1" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			_, _, err := startLoginAgainst(t, "", tc.query)

			// Assert
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestLoginPrintsGroupedCode(
	t *testing.T,
) {
	// Act
	_, output, err := startLoginAgainst(t, "", func(c string) string { return "code=" + c })

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Verification code: A3F9-07C2-1B8E-4D61") {
		t.Errorf("missing the grouped code in %s", output)
	}
	if strings.Contains(output, "last 4") {
		t.Errorf("must not ask for the last 4 characters: %s", output)
	}
}

func TestLoginAgent(
	t *testing.T,
) {
	for _, tc := range []struct {
		name, flag, entrypoint string
		ancestors              []string
		want                   string
	}{
		{name: "flag wins over detection", flag: "copilot", entrypoint: "cli", ancestors: []string{"/usr/local/bin/codex"}, want: "copilot"},
		{name: "invalid flag dropped, detection used", flag: "Claude Code", entrypoint: "cli", want: "claude"},
		{name: "entrypoint means claude", entrypoint: "claude-desktop", want: "claude"},
		{name: "claude ancestor", ancestors: []string{"/bin/zsh", "/Users/a/.local/bin/claude"}, want: "claude"},
		{name: "claude desktop ancestor", ancestors: []string{"/Applications/Claude.app/Contents/MacOS/Claude"}, want: "claude"},
		{name: "codex ancestor", ancestors: []string{"/bin/sh", "/opt/homebrew/bin/codex"}, want: "codex"},
		{name: "codex desktop ancestor", ancestors: []string{"/Applications/Codex.app/Contents/MacOS/Codex"}, want: "codex"},
		{name: "nearest ancestor wins", entrypoint: "cli", ancestors: []string{"/opt/homebrew/bin/codex", "/Users/a/.local/bin/claude"}, want: "codex"},
		{name: "vs code is not copilot", ancestors: []string{"/Applications/Visual Studio Code.app/Contents/MacOS/Electron"}, want: ""},
		{name: "codex home", want: "codex"},
		{name: "unknown", ancestors: []string{"/bin/zsh", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"}, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			env := map[string]string{"CLAUDE_CODE_ENTRYPOINT": tc.entrypoint}
			if tc.name == "codex home" {
				env["CODEX_HOME"] = "/tmp/codex"
			}

			// Act
			got := loginAgent(tc.flag, func(k string) string { return env[k] }, tc.ancestors)

			// Assert
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoginAncestorsWalksNearestFirst(
	t *testing.T,
) {
	// Arrange
	tree := map[int]struct {
		parent int
		exe    string
	}{42: {7, "/bin/zsh"}, 7: {3, "/opt/homebrew/bin/codex"}, 3: {1, "/sbin/launchd"}}

	// Act
	got := loginAncestors("darwin", 42, func(pid int) (int, string) { return tree[pid].parent, tree[pid].exe })

	// Assert
	if strings.Join(got, ",") != "/bin/zsh,/opt/homebrew/bin/codex,/sbin/launchd" {
		t.Fatalf("got %v", got)
	}
	if loginAncestors("windows", 42, nil) != nil {
		t.Fatal("windows has no ps walk")
	}
}
