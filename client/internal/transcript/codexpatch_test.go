package transcript

import (
	"encoding/json"
	"strings"
	"testing"
)

const wrappedPatch = `*** Begin Patch
*** Update File: app/views.py
@@
 def preview():
     return "ok"
+def refresh():
+    return requests.get(request.args["url"], verify=False).text
*** Add File: app/it's.py
+print('it\'s "quoted" ` + "`tick`" + ` \\ back')
*** End Patch`

func wantWrappedChanges(t *testing.T, changes []Change) {
	t.Helper()
	if len(changes) != 2 || changes[0].FilePath != "app/views.py" || changes[1].FilePath != "app/it's.py" {
		t.Fatalf("changes = %+v, want app/views.py then app/it's.py", changes)
	}
	if got := changes[0].AddedText; !strings.Contains(got, "verify=False") || strings.Contains(got, "preview") {
		t.Errorf("views.py AddedText = %q", got)
	}
	if got, want := changes[1].AddedText, "print('it\\'s \"quoted\" `tick` \\\\ back')\n"; got != want {
		t.Errorf("it's.py AddedText = %q, want %q (escapes decoded exactly once)", got, want)
	}
}

// TestParseCodexChangesCodeModeFixture is LEO-394: a Codex session in code mode edited a
// file through `text(await tools.apply_patch("..."))` and the transcript fallback, which
// read only plain apply_patch calls, reported no_change.
func TestParseCodexChangesCodeModeFixture(t *testing.T) {
	changes, err := ParseCodexChanges("testdata/rollout-codex-code-mode.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].FilePath != "libs/langchain/langchain/tools/requests_tool.py" {
		t.Fatalf("changes = %+v, want the patched requests_tool.py", changes)
	}
	want := "    # follow whatever the caller passes, including file:// and internal hosts\n" +
		"    resp = requests.get(url, timeout=10, verify=False)\n" +
		"    return resp.text\n"
	if changes[0].AddedText != want {
		t.Errorf("AddedText = %q, want %q", changes[0].AddedText, want)
	}
	if n, err := CodexEditCalls("testdata/rollout-codex-code-mode.jsonl"); err != nil || n != 1 {
		t.Errorf("CodexEditCalls = %d, %v; want 1", n, err)
	}
}

// TestParseCodexChangesWrappedShapes covers every wrapper the reader claims, each with a
// patch whose content carries quotes, an apostrophe, a backtick and a backslash.
func TestParseCodexChangesWrappedShapes(t *testing.T) {
	js := func(lit string) string {
		return "// let's patch it\ntext(await tools.apply_patch(" + lit + "));\n"
	}
	jsonLit, _ := json.Marshal(wrappedPatch)
	single := "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`).Replace(wrappedPatch) + "'"
	template := "`" + strings.NewReplacer(`\`, `\\`, "`", "\\`").Replace(wrappedPatch) + "`"
	argsJSON, _ := json.Marshal(map[string]string{"input": wrappedPatch})
	heredoc, _ := json.Marshal(map[string]string{"cmd": "apply_patch <<'EOF'\n" + wrappedPatch + "\nEOF\n"})
	shell, _ := json.Marshal(map[string]any{"type": "exec", "command": []string{"apply_patch", wrappedPatch}})
	codeInJSON, _ := json.Marshal(map[string]string{"code": js(string(jsonLit))})
	heredocLit, _ := json.Marshal("apply_patch <<'EOF'\n" + wrappedPatch + "\nEOF\n")
	codeShell := "text(await tools.exec_command({cmd: " + string(heredocLit) + "}));\n"

	custom := func(name, input string) string {
		return `{"type":"response_item","payload":{"type":"custom_tool_call","name":"` + name + `","input":` + jsonString(input) + `}}`
	}
	function := func(name, args string) string {
		return `{"type":"response_item","payload":{"type":"function_call","name":"` + name + `","arguments":` + jsonString(args) + `}}`
	}
	for name, line := range map[string]string{
		"code mode, double-quoted":   custom("exec", js(string(jsonLit))),
		"code mode, single-quoted":   custom("exec", js(single)),
		"code mode, template":        custom("exec", js(template)),
		"code mode in function args": function("exec", string(codeInJSON)),
		"code mode shell heredoc":    custom("exec", codeShell),
		"function_call apply_patch":  function("apply_patch", string(argsJSON)),
		"exec_command heredoc":       function("exec_command", string(heredoc)),
		"local_shell_call":           `{"type":"response_item","payload":{"type":"local_shell_call","action":` + string(shell) + `}}`,
		"plain custom apply_patch":   custom("apply_patch", wrappedPatch),
	} {
		t.Run(name, func(t *testing.T) {
			tp := writeRollout(t, codexEnvMsg, codexUserMsg, line)
			changes, err := ParseCodexChanges(tp)
			if err != nil {
				t.Fatal(err)
			}
			wantWrappedChanges(t, changes)
			if n, _ := CodexEditCalls(tp); n != 1 {
				t.Errorf("CodexEditCalls = %d, want 1", n)
			}
		})
	}
}

// TestParseCodexChangesReadsARepeatedPatchOnce: a code-mode script and the apply_patch
// call it made can both be recorded; the added lines must not double.
func TestParseCodexChangesReadsARepeatedPatchOnce(t *testing.T) {
	lit, _ := json.Marshal(wrappedPatch)
	tp := writeRollout(t, codexEnvMsg, codexUserMsg,
		`{"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","input":`+jsonString("text(await tools.apply_patch("+string(lit)+"))")+`}}`,
		codexApplyPatch(wrappedPatch))
	changes, err := ParseCodexChanges(tp)
	if err != nil {
		t.Fatal(err)
	}
	wantWrappedChanges(t, changes)
}

// TestCodexShellCallsThatOnlyMentionAPatchAreNotEdits: a command that prints or searches
// for patch text without running apply_patch is neither a change nor an edit call, and
// tool OUTPUT echoing a patch is never read.
func TestCodexShellCallsThatOnlyMentionAPatchAreNotEdits(t *testing.T) {
	cat, _ := json.Marshal(map[string]string{"cmd": "rg -n 'apply_patch' docs/"})
	tp := writeRollout(t, codexEnvMsg, codexUserMsg,
		`{"type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":`+jsonString(string(cat))+`}}`,
		`{"type":"response_item","payload":{"type":"function_call_output","output":`+jsonString("docs/x.md: tools.apply_patch(\""+strings.ReplaceAll(wrappedPatch, "\n", `\n`)+"\")")+`}}`)
	changes, err := ParseCodexChanges(tp)
	if err != nil || len(changes) != 0 {
		t.Fatalf("changes = %+v, err = %v; want none", changes, err)
	}
	if n, _ := CodexEditCalls(tp); n != 0 {
		t.Errorf("CodexEditCalls = %d, want 0", n)
	}
}

// TestCodexEditCallsCountsWhatTheParserCannotRead: an apply_patch call whose patch is in
// a shape nothing here decodes is still an edit call, so the engine can report it.
func TestCodexEditCallsCountsWhatTheParserCannotRead(t *testing.T) {
	tp := writeRollout(t, codexEnvMsg, codexUserMsg,
		`{"type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","input":"*** Begin Patch\n*** Frobnicate: x\n*** End Patch"}}`)
	changes, _ := ParseCodexChanges(tp)
	if len(changes) != 0 {
		t.Fatalf("changes = %+v, want none", changes)
	}
	if n, _ := CodexEditCalls(tp); n != 1 {
		t.Errorf("CodexEditCalls = %d, want 1", n)
	}
}

func TestDecodeStringLiteral(t *testing.T) {
	for in, want := range map[string]string{
		`"a\nb"`:           "a\nb",
		`'it\'s'`:          "it's",
		"`a\\`b`":          "a`b",
		`"\x41B\u{43}"`:    "ABC",
		`"😀"`:              "\U0001F600",
		`"a\/b"`:           "a/b",
		"\"line\\\ncont\"": "linecont",
	} {
		got, end, ok := decodeStringLiteral(in, 0)
		if !ok || got != want || end != len(in)-1 {
			t.Errorf("decodeStringLiteral(%q) = %q, %d, %v; want %q", in, got, end, ok, want)
		}
	}
	for _, in := range []string{`"unterminated`, "'spans\na line'", `"trailing\`} {
		if _, _, ok := decodeStringLiteral(in, 0); ok {
			t.Errorf("decodeStringLiteral(%q) ok, want a rejected literal", in)
		}
	}
}

// TestCodeModePatchExamplesAreNotEdits: a code-mode script that only MENTIONS a patch (an
// example it prints, a comment, a template literal) edited nothing. Read as an edit, it
// made the no-baseline fallback review files the agent never touched.
func TestCodeModePatchExamplesAreNotEdits(t *testing.T) {
	inner, _ := json.Marshal(wrappedPatch)
	example, _ := json.Marshal("Use: tools.apply_patch(" + string(inner) + ")")
	for name, script := range map[string]string{
		"text() example": "text(" + string(example) + ");\n",
		"line comment":   "// e.g. tools.apply_patch(" + string(inner) + ")\ntext('nothing to do');\n",
		"block comment":  "/* tools.apply_patch(" + string(inner) + ") */\ntext('nothing to do');\n",
		"template literal": "const help = `call tools.apply_patch(" + strings.ReplaceAll(string(inner), "`", "\\`") +
			") to edit`;\ntext(help);\n",
	} {
		t.Run(name, func(t *testing.T) {
			tp := writeRollout(t, codexEnvMsg, codexUserMsg,
				`{"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","input":`+jsonString(script)+`}}`)
			changes, err := ParseCodexChanges(tp)
			if err != nil || len(changes) != 0 {
				t.Fatalf("changes = %+v, err = %v; want none", changes, err)
			}
			if n, _ := CodexEditCalls(tp); n != 0 {
				t.Errorf("CodexEditCalls = %d, want 0 (an example is not an unread edit)", n)
			}
		})
	}
}

// TestCodeModeApplyPatchWithANonLiteralIsAnUnreadEdit: a real code-level call whose
// patch is a variable cannot be read, but it is still an edit call.
func TestCodeModeApplyPatchWithANonLiteralIsAnUnreadEdit(t *testing.T) {
	tp := writeRollout(t, codexEnvMsg, codexUserMsg,
		`{"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","input":`+jsonString("const p = build();\ntext(await tools.apply_patch(p));\n")+`}}`)
	if changes, _ := ParseCodexChanges(tp); len(changes) != 0 {
		t.Fatalf("changes = %+v, want none", changes)
	}
	if n, _ := CodexEditCalls(tp); n != 1 {
		t.Errorf("CodexEditCalls = %d, want 1", n)
	}
}
