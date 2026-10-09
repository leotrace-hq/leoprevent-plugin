package prpost

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// THE RESOLVE HALF — reading this lane's own review threads, and marking one resolved.
//
// ⚠️ IT IS GRAPHQL-ONLY, AND THAT IS GITHUB'S CONSTRAINT RATHER THAN A CHOICE. The REST API
// can create a review comment and can reply to one; it has no endpoint that collapses one.
// The `reviewThreads` connection is also the only way to learn which of our comments are
// still open, so one query answers both halves at once: which findings are outstanding, and
// the handle needed to close each.
//
// ⚠️ TWO MUTATIONS, TRIED IN ORDER, AND THE ORDER IS A PERMISSION FACT MEASURED AGAINST A
// LIVE INSTALLATION RATHER THAN GUESSED AT.
//
//   - `resolveReviewThread` closes the CONVERSATION, which is what a reviewer means by
//     resolved: the thread collapses and the pull request's "N unresolved conversations"
//     counter drops. It needs PUSH ACCESS TO THE REPOSITORY, which for an App is
//     `contents: write`. With `contents: read` it answers
//     `FORBIDDEN: Resource not accessible by integration`, whatever else the App holds —
//     `pull_requests: write` does not buy it.
//   - `minimizeComment(classifier: RESOLVED)` collapses OUR COMMENT under GitHub's own
//     "marked as resolved" and needs nothing beyond having written it. The thread stays open.
//
// ⚠️ THE FALLBACK IS NOT BELT-AND-BRACES, IT IS THE ROLLOUT. Adding a permission to an App
// does NOT apply to existing installations: GitHub mails every org owner and each installation
// keeps the old set until a human accepts. So at any moment some installations have
// `contents: write` and some do not, for as long as it takes them to accept — and an
// installation in the second group must still get its fixed findings closed rather than
// nothing at all. Trying the stronger mutation first and falling back costs one refused
// round trip on those installations and keeps the weaker outcome available to them.
//
// ⚠️ AND THE REFUSAL MUST NOT BE READ AS A FAILURE. `MarkResolved` reports which of the two
// happened so the caller can log it; a thread it could only minimize is still a finding this
// lane closed.
//
// ⚠️ IT IS SAFE TO CLOSE OUR OWN THREADS BECAUSE THIS LANE BLOCKS NOTHING. The review posts as
// COMMENT, never REQUEST_CHANGES, so the worst a wrong close can do is collapse a conversation
// a reviewer then re-opens — GitHub keeps the button. What it must never do is touch somebody
// ELSE'S thread, which is what `viewerDidAuthor` is read for below.

// maxThreadPages bounds the thread walk, as maxCommentPages bounds the comment walk.
//
// ⚠️ IT FAILS TOWARD LEAVING THREADS OPEN. A truncated or failed walk returns fewer
// threads, so the worst outcome is a fixed finding whose comment stays open one push
// longer — where returning a thread we could not verify would resolve a live finding's
// comment, which is the direction this must never fail in.
const maxThreadPages = 5

// threadsPerPage is GraphQL's own maximum for a connection.
const threadsPerPage = 100

// ReviewThread is one of our own posted findings, as it stands on the pull request.
type ReviewThread struct {
	// ID is the thread's GraphQL node id. Read for logging and for nothing else: the
	// mutation acts on the COMMENT, for the permission reason above.
	ID string
	// CommentID is the node MarkResolved collapses.
	CommentID string
	// Marker is the finding marker the thread's first comment carries: this is what
	// identifies WHICH finding the thread is about, parsed by the same parseMarker the
	// de-duplication uses.
	Marker string
	// ReviewID is the review that raised the finding, from the second hidden marker.
	// Empty on a comment posted before that marker existed, which is why a resolution
	// pass must be able to skip a thread rather than guess.
	ReviewID string
	// Commit is the commit the comment was originally written against — the BEFORE side
	// of any later re-judge. Empty when GitHub did not report one.
	Commit string
	// Resolved is GitHub's own state, so a run never re-closes what is already closed. It is
	// the OR of two of them: a thread a human resolved, and a comment we already minimized.
	// Either means the conversation is finished, and re-judging it would buy a second opinion
	// nobody asked for at Opus prices.
	Resolved bool
	// Mine reports whether the authenticated app wrote the thread's first comment.
	Mine bool
}

// graphQLRequest is the wire shape of a GraphQL POST.
type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

// graphQLError is one entry of the `errors` array.
//
// ⚠️ A GRAPHQL FAILURE ARRIVES AS HTTP 200 WITH AN `errors` ARRAY, WHICH IS WHY THIS TYPE
// EXISTS AT ALL. `do`'s status check cannot see it, so a caller that only checked the
// status would read a permission refusal, a malformed query or a rate limit as a
// successful response carrying no threads — and "no threads" is indistinguishable from
// "nothing left to resolve". Every caller here must treat an error array as a failure.
type graphQLError struct {
	Message string `json:"message"`
}

// graphQL issues one GraphQL call and unmarshals `data` into out.
func (c Client) graphQL(query string, vars map[string]any, out any) error {
	// The path is taken from the ORIGIN rather than the REST root: on Enterprise the two
	// APIs are siblings (`/api/v3` and `/api/graphql`), so appending would address a path
	// that does not exist. See doAtOrigin.
	data, _, err := c.doAtOrigin(http.MethodPost, c.graphQLPath(), graphQLRequest{Query: query, Variables: vars})
	if err != nil {
		return err
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphQLError  `json:"errors"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("github graphql: unreadable response: %w", err)
	}
	if len(env.Errors) > 0 {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, e.Message)
		}
		return fmt.Errorf("github graphql: %s", firstLine(strings.Join(msgs, "; ")))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("github graphql: unreadable data: %w", err)
	}
	return nil
}

// graphQLPath is where GraphQL lives relative to the API ORIGIN.
//
// github.com serves it at `/graphql`; Enterprise Server serves REST at `/api/v3` and
// GraphQL at `/api/graphql`, so the answer is derived from the configured root's own path
// rather than hardcoded. An unrecognised root keeps `/graphql`, which is the github.com
// shape and the one a proxy is most likely to mirror.
func (c Client) graphQLPath() string {
	root, err := c.api()
	if err != nil || root.Path == "" {
		return "/graphql"
	}
	if strings.HasSuffix(root.Path, "/api/v3") {
		return strings.TrimSuffix(root.Path, "/v3") + "/graphql"
	}
	return root.Path + "/graphql"
}

const threadsQuery = `query($owner:String!,$repo:String!,$pr:Int!,$after:String){
  repository(owner:$owner,name:$repo){
    pullRequest(number:$pr){
      reviewThreads(first:100,after:$after){
        pageInfo{hasNextPage endCursor}
        nodes{
          id
          isResolved
          comments(first:1){
            nodes{ id body viewerDidAuthor isMinimized originalCommit{ oid } }
          }
        }
      }
    }
  }
}`

// ReviewThreads returns every review thread on the pull request that THIS app wrote and
// that carries one of our finding markers.
//
// Threads we did not author are dropped here rather than by the caller, so no code path
// downstream can be handed a handle to somebody else's conversation. A thread of ours with
// no readable marker is dropped too: it names no finding, so there is nothing a re-judge
// could decide about it.
func (c Client) ReviewThreads(pr int) ([]ReviewThread, error) {
	var out []ReviewThread
	var after any
	for page := 0; page < maxThreadPages; page++ {
		var resp struct {
			Repository struct {
				PullRequest struct {
					ReviewThreads struct {
						PageInfo struct {
							HasNextPage bool   `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
						Nodes []struct {
							ID         string `json:"id"`
							IsResolved bool   `json:"isResolved"`
							Comments   struct {
								Nodes []struct {
									ID              string `json:"id"`
									Body            string `json:"body"`
									ViewerDidAuthor bool   `json:"viewerDidAuthor"`
									IsMinimized     bool   `json:"isMinimized"`
									OriginalCommit  *struct {
										OID string `json:"oid"`
									} `json:"originalCommit"`
								} `json:"nodes"`
							} `json:"comments"`
						} `json:"nodes"`
					} `json:"reviewThreads"`
				} `json:"pullRequest"`
			} `json:"repository"`
		}
		vars := map[string]any{"owner": c.Owner, "repo": c.Repo, "pr": pr, "after": after}
		if err := c.graphQL(threadsQuery, vars, &resp); err != nil {
			// Partial is better than nothing and strictly safer: every thread already
			// collected is one we may still be able to close, and the ones we never saw
			// simply stay open. Reported so a persistent failure is visible.
			return out, err
		}
		conn := resp.Repository.PullRequest.ReviewThreads
		for _, n := range conn.Nodes {
			if len(n.Comments.Nodes) == 0 {
				continue
			}
			first := n.Comments.Nodes[0]
			// ⚠️ AUTHORSHIP IS THE GUARD, NOT THE MARKER. A marker is text anybody can type
			// into a review comment, so keying only on it would let a human thread carrying
			// our marker be resolved by us — closing somebody's question as though we had
			// answered it. `viewerDidAuthor` is the app's own identity as GitHub sees it, so
			// it needs no name matching and cannot be spoofed by content.
			if !first.ViewerDidAuthor {
				continue
			}
			m := markerIn(first.Body)
			if m == "" {
				continue
			}
			t := ReviewThread{
				ID:        n.ID,
				CommentID: first.ID,
				Marker:    m,
				ReviewID:  ReviewIDIn(first.Body),
				Resolved:  n.IsResolved || first.IsMinimized,
				Mine:      true,
			}
			if first.OriginalCommit != nil {
				t.Commit = first.OriginalCommit.OID
			}
			out = append(out, t)
		}
		if !conn.PageInfo.HasNextPage || conn.PageInfo.EndCursor == "" {
			break
		}
		after = conn.PageInfo.EndCursor
	}
	return out, nil
}

const resolveMutation = `mutation($id:ID!){ resolveReviewThread(input:{threadId:$id}){ thread{ id isResolved } } }`

const minimizeMutation = `mutation($id:ID!){ minimizeComment(input:{subjectId:$id,classifier:RESOLVED}){ minimizedComment{ isMinimized minimizedReason } } }`

// Closed says how far MarkResolved got, so a caller can log the difference rather than
// treating a narrower outcome as a failure.
type Closed string

const (
	// ClosedThread: the conversation is resolved. What a reviewer means by resolved.
	ClosedThread Closed = "thread"
	// ClosedComment: only our comment is collapsed, because the installation has not
	// accepted `contents: write`. The thread stays open.
	ClosedComment Closed = "comment"
)

// MarkResolved closes one finding's conversation, falling back to collapsing our own comment
// where the installation's permissions do not reach.
//
// Both ids must have come from ReviewThreads, which is what guarantees the thread is one this
// app wrote: there is no other way into this function, and closing a conversation is the one
// thing this lane does to a pull request after the fact.
func (c Client) MarkResolved(threadID, commentID string) (Closed, error) {
	if strings.TrimSpace(threadID) == "" && strings.TrimSpace(commentID) == "" {
		return "", fmt.Errorf("github graphql: no thread or comment to resolve")
	}
	if threadID != "" {
		err := c.graphQL(resolveMutation, map[string]any{"id": threadID}, nil)
		if err == nil {
			return ClosedThread, nil
		}
		// Anything OTHER than a permission refusal is returned as-is: a network failure or a
		// malformed id is not a reason to reach for the weaker mutation, and retrying it would
		// hide the real error behind a second one.
		if !isForbidden(err) || commentID == "" {
			return "", err
		}
	}
	if err := c.graphQL(minimizeMutation, map[string]any{"id": commentID}, nil); err != nil {
		return "", err
	}
	return ClosedComment, nil
}

// isForbidden reports whether GitHub refused for want of a permission.
//
// Matched on the message because GraphQL reports this as an errors entry rather than a status
// (see graphQLError), and the `type` field is not surfaced by the thin envelope above. A miss
// costs the fallback, which is the safe direction: the finding's comment simply stays open and
// the real error is reported.
func isForbidden(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not accessible by integration")
}
