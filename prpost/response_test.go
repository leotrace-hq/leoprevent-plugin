package prpost

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type countedResponseBody struct {
	io.Reader
	read   int
	closed bool
}

func (b *countedResponseBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}

func (b *countedResponseBody) Close() error { b.closed = true; return nil }

// Valid JSON followed by whitespace must still be refused when it exceeds the limit:
// accepting a parseable prefix would conceal overflow just as cutting a tree mid-string does.
func TestGitHubResponseLimits(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tree      bool
		truncated bool
		limit     int
		extra     int
	}{
		{name: "complete tree at limit", tree: true, limit: 8 << 20},
		{name: "GitHub truncated tree at limit", tree: true, truncated: true, limit: 8 << 20},
		{name: "tree one byte over", tree: true, limit: 8 << 20, extra: 1},
		{name: "tree read stays bounded", tree: true, limit: 8 << 20, extra: 1024},
		{name: "raw file at unchanged limit", limit: 4 << 20},
		{name: "raw file one byte over", limit: 4 << 20, extra: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := `{"tree":[],"truncated":false}`
			if tc.truncated {
				prefix = `{"tree":[],"truncated":true}`
			}
			body := &countedResponseBody{Reader: strings.NewReader(prefix + strings.Repeat(" ", tc.limit+tc.extra-len(prefix)))}
			c := Client{Owner: "acme", Repo: "api", HTTP: &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
				// No Content-Length: chunked responses must have the same bound.
				return &http.Response{StatusCode: http.StatusOK, Body: body, ContentLength: -1}, nil
			})}}
			var err error
			if tc.tree {
				var paths []string
				var complete bool
				paths, complete, err = c.Tree("HEAD")
				if tc.extra > 0 && (len(paths) != 0 || complete) {
					t.Errorf("overflow returned paths=%v, complete=%v", paths, complete)
				}
				if tc.extra == 0 && complete != !tc.truncated {
					t.Errorf("complete=%v, GitHub truncated=%v", complete, tc.truncated)
				}
			} else {
				var content string
				var ok bool
				content, ok, err = c.FileContent("src/app.go", "HEAD")
				if tc.extra > 0 && (content != "" || ok) {
					t.Errorf("overflow returned %d bytes, ok=%v", len(content), ok)
				}
				if tc.extra == 0 && (len(content) != tc.limit || !ok) {
					t.Errorf("got %d bytes, ok=%v at the limit", len(content), ok)
				}
			}
			if tc.extra > 0 {
				if err == nil || !strings.Contains(err.Error(), "response exceeds") {
					t.Fatalf("overflow error=%v, want an explicit response-size error", err)
				}
				if body.read != tc.limit+1 {
					t.Errorf("read %d bytes, want only the limit plus one", body.read)
				}
			} else {
				if err != nil {
					t.Fatalf("response at limit: %v", err)
				}
				if body.read != tc.limit {
					t.Errorf("read %d bytes, want the whole %d-byte response", body.read, tc.limit)
				}
			}
			if !body.closed {
				t.Error("response body was not closed")
			}
		})
	}
}
