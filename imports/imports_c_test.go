package imports

import (
	"reflect"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
)

// The callee shape C context exists for: the added code passes a length into an
// in-repo helper, and only the helper's body shows the copy it does with it.
const cReadH = `#ifndef READ_H
#define READ_H
#include <stdio.h>

#define READ_BUF_LEN 256

/* Read n bytes from f into buf. */
int readBytes(FILE *f, char *buf, int n);
int readUInt8(FILE *f);

#endif
`

const cReadC = `#include <string.h>
#include "read.h"

static char scratch[READ_BUF_LEN];

int
readBytes (FILE *f, char *buf, int n)
{
	fread(scratch, 1, n, f);
	memcpy(buf, scratch, n);
	return n;
}

int readUInt8(FILE *f)
{
	int c = fgetc(f);
	if (c == EOF) {
		return 0;
	}
	return c;
}
`

func TestCResolvesTheHeaderAndTheFileDefiningTheCall(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"util/read.h": cReadH,
		"util/read.c": cReadC,
		"util/log.h":  "void logMsg(const char *m);\n",
		"src/main.c":  "",
	})
	ch := Change{
		FilePath:    "src/main.c",
		AddedText:   "\tchar name[32];\n\treadBytes(f, name, len);\n",
		FullContent: "#include <stdio.h>\n#include \"../util/read.h\"\n#include \"util/log.h\"\nvoid f(FILE *f, int len) {\n\tchar name[32];\n\treadBytes(f, name, len);\n}\n",
	}
	got := paths(resolve(t, root, ch))
	if want := []string{"util/read.c", "util/read.h"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v (the referenced header and its definition, not log.h or stdio.h), got %v", want, got)
	}
}

func TestCQuotedIncludeFallsBackToTheIndex(t *testing.T) {
	// `#include "util/read.h"` from src/ only compiles with -I at the root. The index
	// suffix match stands in for that -I path.
	root := writeRepo(t, map[string]string{
		"util/read.h": cReadH,
		"util/read.c": cReadC,
	})
	ch := Change{
		FilePath:    "src/main.c",
		AddedText:   "readUInt8(f);\n",
		FullContent: "#include \"util/read.h\"\nreadUInt8(f);\n",
	}
	if got := paths(resolve(t, root, ch)); !reflect.DeepEqual(got, []string{"util/read.c", "util/read.h"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCAMacroPullsTheHeaderButNotTheSourceFile(t *testing.T) {
	// For an out-of-bounds bug the deciding fact is often only in the header: the
	// buffer's real size. Nothing in read.c is called, so read.c stays home.
	root := writeRepo(t, map[string]string{
		"include/proj/read.h": cReadH,
		"src/read.c":          cReadC,
	})
	ch := Change{
		FilePath:    "src/parse.c",
		AddedText:   "char out[READ_BUF_LEN];\nmemcpy(out, in, n);\n",
		FullContent: "#include <proj/read.h>\nchar out[READ_BUF_LEN];\nmemcpy(out, in, n);\n",
	}
	if got := paths(resolve(t, root, ch)); !reflect.DeepEqual(got, []string{"include/proj/read.h"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCAngleIncludeFindsTheDefinitionByBaseName(t *testing.T) {
	// include/proj/read.h → src/read.c: the libxml2 layout, where the header and the
	// file defining it are in different trees.
	root := writeRepo(t, map[string]string{
		"include/proj/read.h": cReadH,
		"src/read.c":          cReadC,
	})
	ch := Change{
		FilePath:    "tools/dump.c",
		AddedText:   "readBytes(f, buf, n);\n",
		FullContent: "#include <proj/read.h>\nreadBytes(f, buf, n);\n",
	}
	if got := paths(resolve(t, root, ch)); !reflect.DeepEqual(got, []string{"include/proj/read.h", "src/read.c"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCAmbiguousDefinitionResolvesToNothing(t *testing.T) {
	// Two read.c files and no sibling: either could be the definition, and sending the
	// wrong one costs bytes for code the change does not run.
	root := writeRepo(t, map[string]string{
		"include/proj/read.h": cReadH,
		"a/read.c":            cReadC,
		"b/read.c":            cReadC,
	})
	ch := Change{
		FilePath:    "tools/dump.c",
		AddedText:   "readBytes(f, buf, n);\n",
		FullContent: "#include <proj/read.h>\nreadBytes(f, buf, n);\n",
	}
	if got := paths(resolve(t, root, ch)); !reflect.DeepEqual(got, []string{"include/proj/read.h"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCNearestHeaderWinsASuffixTie(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"liba/config.h": "#define MAX_NAME 16\n",
		"libb/config.h": "#define MAX_NAME 4096\n",
	})
	ch := Change{
		FilePath:    "libb/src/name.c",
		AddedText:   "char n[MAX_NAME];\n",
		FullContent: "#include <config.h>\nchar n[MAX_NAME];\n",
	}
	if got := paths(resolve(t, root, ch)); !reflect.DeepEqual(got, []string{"libb/config.h"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCGateSkipsUnreferencedAndVendoredHeaders(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"util/read.h":             cReadH,
		"third_party/zlib/zlib.h": "int inflate(void *strm, int flush);\n",
	})
	ch := Change{
		FilePath:    "main.c",
		AddedText:   "inflate(&s, 0);\nint x = 1 + 2;\n",
		FullContent: "#include \"util/read.h\"\n#include \"third_party/zlib/zlib.h\"\ninflate(&s, 0);\nint x = 1 + 2;\n",
	}
	if got := resolve(t, root, ch); len(got) != 0 {
		t.Fatalf("want no context (read.h unreferenced, zlib vendored), got %v", paths(got))
	}
}

func TestCDeclaredReadsDeclarationsNotBodies(t *testing.T) {
	body := `#define HDR_LEN 8
typedef unsigned int u32;
typedef int (*read_fn)(void *ctx);
typedef struct {
	u32 len;
	char data[64];
} Packet;
enum kind { KIND_A = 1, KIND_B,
	KIND_C
};
extern int g_debug;
int parse(Packet *p) __attribute__((format(printf, 1, 2)));
static inline int clamp(int v) {
	return memcpy_s(v);
}
`
	names, funcs := cDeclared(body)
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for _, want := range []string{"HDR_LEN", "u32", "read_fn", "Packet", "kind", "KIND_C", "g_debug", "parse", "clamp"} {
		if !set[want] {
			t.Errorf("missing declared name %q in %v", want, names)
		}
	}
	// A field, a call inside an inline body and an attribute argument are not
	// declarations: gating on them would pull this header for any `len` or `printf`.
	for _, not := range []string{"len", "data", "memcpy_s", "printf", "format"} {
		if set[not] {
			t.Errorf("%q is not declared by the header, got %v", not, names)
		}
	}
	if !reflect.DeepEqual(funcs, []string{"parse", "clamp"}) {
		t.Errorf("funcs = %v, want [parse clamp]", funcs)
	}
}

// ---- slicer ----

const cHelper = `#include <string.h>
#include "buf.h"

#define COPY(d, s, n) do { \
	memcpy((d), (s), (n)); \
} while (0)

static int table[4] = { 1, 2, 3, 4 };

/*
 * Copy a payload into dst. The caller sizes dst.
 */
static int
copy_payload (char *dst,
              const char *src, size_t n)
{
	COPY(dst, src, n);
	return check(n);
}

static int check(size_t n)
{
	if (n > sizeof(table)) {
		return -1;
	}
	return 0;
}

int render_page(struct page *p) {
	for (int i = 0; i < p->rows; i++) {
		draw_row(p, i);
		draw_row(p, i + 1);
		draw_row(p, i + 2);
	}
	return 0;
}

int send_mail(const char *to) {
	struct smtp *c = smtp_open("localhost");
	smtp_send(c, to);
	smtp_close(c);
	return 0;
}
`

func TestSliceCKeepsTheCalledFunctionInGNUStyle(t *testing.T) {
	excerpt, nums, ok := sliceFile("buf.c", cHelper, map[string]bool{"copy_payload": true}, limits.MaxContextFileBytes, true)
	if !ok {
		t.Fatal("expected the C helper to slice")
	}
	checkLines(t, cHelper, excerpt, nums)
	for _, want := range []string{
		"COPY(dst, src, n);",                                                   // the reached body
		"memcpy((d), (s), (n)); \\",                                            // the macro it expands to: a directive, always kept
		"if (n > sizeof(table)) {",                                             // check(), one call away
		"static int table[4] = { 1, 2, 3, 4 };",                                // module-level data
		"static int\n",                                                         // the return type above the name travels with the header
		"The caller sizes dst.",                                                // the reached function's doc
		"int render_page(struct page *p) {", "int send_mail(const char *to) {", // signatures stay
	} {
		if !strings.Contains(excerpt, want) {
			t.Errorf("excerpt lost %q:\n%s", want, excerpt)
		}
	}
	for _, gone := range []string{"draw_row", "smtp_send"} {
		if strings.Contains(excerpt, gone) {
			t.Errorf("excerpt kept the unreached body holding %q:\n%s", gone, excerpt)
		}
	}
}

func TestSliceCDropsTheDocOfAnUnreachedPrototype(t *testing.T) {
	var b strings.Builder
	b.WriteString("#ifndef API_H\n#define API_H\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n")
	for _, n := range []string{"open_stream", "close_stream", "seek_stream", "read_stream"} {
		b.WriteString("/**\n * " + strings.Repeat("Long reference documentation for this call. ", 4) + "\n */\n")
		b.WriteString("int " + n + "(void *s,\n\tint flags);\n\n")
	}
	b.WriteString("#ifdef __cplusplus\n}\n#endif\n#endif\n")
	hdr := b.String()

	excerpt, nums, ok := sliceFile("api.h", hdr, map[string]bool{"read_stream": true}, limits.MaxContextFileBytes, true)
	if !ok {
		t.Fatal("expected the header to slice (extern \"C\" guard is balanced)")
	}
	checkLines(t, hdr, excerpt, nums)
	for _, n := range []string{"open_stream", "close_stream", "seek_stream", "read_stream"} {
		if !strings.Contains(excerpt, "int "+n+"(void *s,") {
			t.Errorf("prototype %s dropped:\n%s", n, excerpt)
		}
	}
	if got := strings.Count(excerpt, "Long reference documentation"); got != 4 {
		// one per line of the kept doc block × the one reached prototype
		t.Errorf("want only read_stream's doc kept (4 repeats on one line), got %d:\n%s", got, excerpt)
	}
}

func TestSliceCSendsAFileWithBranchUnbalancedBracesWhole(t *testing.T) {
	// Two signatures for one body: a brace count reading both #if branches sees two
	// opens and one close, and every span after it would be misplaced.
	src := "#ifdef WIDE\nint copy(wchar_t *d, size_t n) {\n#else\nint copy(char *d, size_t n) {\n#endif\n\tmemcpy(d, src, n);\n\treturn 0;\n}\n\nint other(void) {\n\treturn 1;\n}\n"
	if spans := cSpans(strings.Split(src, "\n")); spans != nil {
		t.Fatalf("want no spans for a branch-unbalanced file, got %+v", spans)
	}
}

func TestSliceCDoesNotGiveAMacroLineTheNextBody(t *testing.T) {
	// DECLARE_ITEM(x) has no semicolon. Read as a declaration it would claim
	// handle_item's body under a name nothing calls, and drop it.
	src := "DECLARE_ITEM(widget)\nint handle_item(int n)\n{\n\treturn table[n];\n}\n"
	spans := cSpans(strings.Split(src, "\n"))
	if len(spans) != 1 || spans[0].name != "handle_item" {
		t.Fatalf("want one span named handle_item, got %+v", spans)
	}
}

func TestSliceCFindsCppMethodsInContainers(t *testing.T) {
	src := `namespace net {
class Reader {
public:
	int read(char *buf, int n) {
		return fill(buf, n);
	}
};

int Reader::fill(char *buf, int n)
{
	memcpy(buf, src_, n);
	return n;
}
}  // namespace net
`
	var names []string
	for _, sp := range cSpans(strings.Split(src, "\n")) {
		names = append(names, sp.name)
	}
	if !reflect.DeepEqual(names, []string{"read", "fill"}) {
		t.Fatalf("want [read fill], got %v", names)
	}
}

func TestSliceCSkipsKAndRDefinitions(t *testing.T) {
	// K&R parameter declarations sit between ) and {. Not recognised → kept whole.
	src := "int old(a, n)\nchar *a;\nint n;\n{\n\treturn a[n];\n}\n"
	for _, sp := range cSpans(strings.Split(src, "\n")) {
		if sp.end > sp.headEnd {
			t.Fatalf("K&R definition read as a span with a body: %+v", sp)
		}
	}
}

func TestCFindsTheFileNamedAfterTheFunction(t *testing.T) {
	// One umbrella header, one function per file (the c-ares layout): no file is named
	// after the header, but the definition is in the file named after the function.
	root := writeRepo(t, map[string]string{
		"include/ares.h":         "int ares_init(void);\nint ares_query(const char *name, int len);\n",
		"src/lib/ares_init.c":    "int ares_init(void)\n{\n\treturn 0;\n}\n",
		"src/lib/ares_query.c":   "int ares_query(const char *name, int len)\n{\n\treturn len;\n}\n",
		"src/lib/ares_process.c": "",
	})
	ch := Change{
		FilePath:    "src/lib/ares_process.c",
		AddedText:   "ares_query(buf, n);\n",
		FullContent: "#include <ares.h>\nares_query(buf, n);\n",
	}
	if got := paths(resolve(t, root, ch)); !reflect.DeepEqual(got, []string{"include/ares.h", "src/lib/ares_query.c"}) {
		t.Fatalf("want the header and ares_query.c (not ares_init.c), got %v", got)
	}
}
