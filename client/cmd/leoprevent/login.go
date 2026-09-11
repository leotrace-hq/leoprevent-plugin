package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

type loginResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri_complete"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Key             string `json:"license_key"`
	LicenseID       string `json:"license_id"`
	AccountID       string `json:"account_id"`
	DeviceID        string `json:"device_id"`
	Error           string `json:"error"`
}

func loginURL(
	raw string,
) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Host == "" {
		return "", errors.New("login requires a server and dashboard origin without a path, query, or credentials")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return "", errors.New("login requires HTTPS, except for a loopback development server")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func loginRequest(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	body any,
	key string,
) (loginResponse, int, error) {
	var out loginResponse
	var reader io.Reader
	method := http.MethodGet
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return out, 0, errors.New("could not prepare login request")
		}
		reader = bytes.NewReader(encoded)
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return out, 0, errors.New("invalid login endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	res, err := client.Do(req)
	if err != nil {
		return out, 0, errors.New("login network request failed; check your connection and try again")
	}
	defer res.Body.Close()
	if err := json.NewDecoder(io.LimitReader(res.Body, 16384)).Decode(&out); err != nil {
		return out, res.StatusCode, errors.New("login service returned an invalid response")
	}
	return out, res.StatusCode, nil
}

func openLoginBrowser(
	address string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", address)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", address)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", address)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func runLogin(
	args []string,
) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	noBrowser := fs.Bool("no-browser", false, "show the verification URL without opening a browser")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: leoprevent-plugin login [--no-browser]")
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Login configuration could not be loaded.")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 11*time.Minute)
	defer timeout()
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	returnApp := loginReturnApp(*noBrowser, runtime.GOOS, os.Getenv, os.Getppid(), loginParentProcess)
	if err := performLogin(ctx, cfg, client, *noBrowser, os.Stdout, openLoginBrowser); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		fmt.Fprintln(os.Stderr, "The saved credential has not been replaced.")
		return 1
	}
	finishLogin(returnApp, os.Stdout, activateLoginApp)
	return 0
}

func performLogin(
	ctx context.Context,
	cfg *config.Config,
	client *http.Client,
	noBrowser bool,
	out io.Writer,
	openBrowser func(string) error,
) error {
	if cfg.Tier != config.TierCloud {
		return errors.New("browser login currently supports cloud licenses only; use set-license for a local-tier license")
	}
	server, err := loginURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	portal, err := loginURL(cfg.DashboardURL)
	if err != nil {
		return err
	}
	if cfg.LicenseKey != "" {
		fmt.Fprintln(out, "An existing credential is configured. It will be replaced only after the new login is verified.")
	}
	host, _ := os.Hostname()
	if host == "" {
		host = runtime.GOOS + " installation"
	}
	started, status, err := loginRequest(ctx, client, portal+"/api/device-login", map[string]string{"action": "start", "server": server, "device": host}, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(started.DeviceCode) || !regexp.MustCompile(`^[A-F0-9]{16}$`).MatchString(started.UserCode) || started.ExpiresIn <= 0 || started.ExpiresIn > 600 || started.Interval < 1 || started.Interval > 30 {
		return errors.New("login could not start; check that this portal and server support browser login in the same environment")
	}
	verification, err := url.Parse(started.VerificationURI)
	if err != nil || verification.User != nil || verification.Scheme+"://"+verification.Host != portal || verification.Path != "/device" || verification.Fragment != "" || verification.RawQuery != "code="+started.UserCode {
		return errors.New("login returned an invalid verification URL")
	}
	fmt.Fprintf(out, "Open %s\nVerification code: %s\nConfirm the account and installation in your browser. Press Ctrl+C to cancel.\n", started.VerificationURI, started.UserCode)
	if !noBrowser {
		if err := openBrowser(started.VerificationURI); err != nil {
			fmt.Fprintln(out, "Could not open a browser. Open the verification URL above on another device.")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(started.ExpiresIn)*time.Second)
	defer cancel()
	interval := time.Duration(started.Interval) * time.Second
	for {
		select {
		case <-ctx.Done():
			return errors.New("login canceled or expired; run login again")
		case <-time.After(interval):
		}
		result, status, err := loginRequest(ctx, client, portal+"/api/device-login", map[string]string{"action": "poll", "device_code": started.DeviceCode}, "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			switch result.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += 5 * time.Second
				continue
			case "access_denied":
				return errors.New("login was canceled or the account is not eligible; ask your administrator if access is required")
			case "expired_token":
				return errors.New("login expired or was already redeemed; run login again")
			default:
				return errors.New("login service is unavailable; try again")
			}
		}
		if !strings.HasPrefix(result.Key, "lp_live_") || result.LicenseID == "" || result.AccountID == "" || result.DeviceID == "" {
			return errors.New("login returned an invalid credential response")
		}
		validated := false
		for attempt := 0; attempt < 9; attempt++ {
			identity, status, err := loginRequest(ctx, client, server+"/auth/validate", nil, result.Key)
			if err == nil && status == http.StatusOK && identity.AccountID == result.AccountID && identity.LicenseID == result.LicenseID {
				validated = true
				break
			}
			if attempt < 8 {
				select {
				case <-ctx.Done():
					return errors.New("login canceled before credential validation")
				case <-time.After(5 * time.Second):
				}
			}
		}
		if !validated {
			return errors.New("the review server could not validate the new credential; check the environment and try again")
		}
		if _, err := config.SaveLoginLicense(result.Key, server, portal, result.DeviceID); err != nil {
			return errors.New("login was authorized but the credential could not be saved")
		}
		if os.Getenv(config.EnvLicenseKey) != "" {
			fmt.Fprintln(out, "LEOPREVENT_LICENSE_KEY overrides the saved credential. Remove that override to use this login.")
		}
		return nil
	}
}

func loginReturnApp(
	noBrowser bool,
	platform string,
	getenv func(string) string,
	pid int,
	parent func(int) (int, string),
) string {
	if noBrowser || platform != "darwin" || getenv("SSH_CONNECTION") != "" || getenv("SSH_TTY") != "" {
		return ""
	}
	entrypoint := getenv("CLAUDE_CODE_ENTRYPOINT")
	if strings.HasPrefix(entrypoint, "remote") {
		return ""
	}
	if entrypoint == "claude-desktop" || entrypoint == "claude-desktop-3p" {
		return "com.anthropic.claudefordesktop"
	}
	for depth := 0; pid > 1 && depth < 16; depth++ {
		next, executable := parent(pid)
		for _, app := range []struct{ path, bundle string }{
			{"/Claude.app/Contents/", "com.anthropic.claudefordesktop"},
			{"/Codex.app/Contents/", "com.openai.codex"},
			{"/ChatGPT.app/Contents/", "com.openai.codex"},
			{"/Visual Studio Code.app/Contents/", "com.microsoft.VSCode"},
			{"/Terminal.app/Contents/", "com.apple.Terminal"},
			{"/iTerm.app/Contents/", "com.googlecode.iterm2"},
		} {
			if strings.Contains(executable, app.path) {
				return app.bundle
			}
		}
		if next == pid || next <= 1 {
			break
		}
		pid = next
	}
	switch getenv("TERM_PROGRAM") {
	case "Apple_Terminal":
		return "com.apple.Terminal"
	case "iTerm.app":
		return "com.googlecode.iterm2"
	case "vscode":
		return "com.microsoft.VSCode"
	}
	return ""
}

func loginParentProcess(
	pid int,
) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "ppid=,comm=").Output()
	if err != nil {
		return 0, ""
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, ""
	}
	parent, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, ""
	}
	return parent, strings.Join(fields[1:], " ")
}

func finishLogin(
	app string,
	out io.Writer,
	activate func(string) error,
) {
	if app != "" {
		if err := activate(app); err != nil {
			fmt.Fprintln(out, "Switch back to the app where you started login.")
		}
	}
	fmt.Fprintln(out, "Connected to LeoPrevent.")
}

func activateLoginApp(
	bundleID string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "open", "-b", bundleID)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
