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
	err := performLogin(context.Background(), &config.Config{ServerURL: server.URL, DashboardURL: server.URL, Tier: "cloud"}, server.Client(), false, &output, func(string) error { return errors.New("no browser") })
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
	err = performLogin(ctx, &config.Config{ServerURL: server.URL, DashboardURL: server.URL, Tier: "cloud"}, server.Client(), true, &bytes.Buffer{}, func(string) error { t.Fatal("browser opened"); return nil })
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
	err = performLogin(ctx, cfg, client, os.Getenv("LEO234_BROWSER_AUTO") != "1", os.Stdout, openLoginBrowser)
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
			err = performLogin(ctx, &config.Config{ServerURL: server.URL, DashboardURL: server.URL, Tier: "cloud"}, server.Client(), true, &bytes.Buffer{}, func(string) error { return nil })
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
		if output.String() != "Connected to LeoPrevent.\n" {
			t.Fatalf("unexpected output: %s", &output)
		}
		if (app == "" && calls != 0) || (app != "" && calls != 1) {
			t.Fatal("unexpected activation")
		}
	}
	var output bytes.Buffer
	finishLogin("com.apple.Terminal", &output, func(string) error { return errors.New("unavailable") })
	if !strings.Contains(output.String(), "Switch back") || !strings.Contains(output.String(), "Connected to LeoPrevent.") {
		t.Fatal(output.String())
	}
}
