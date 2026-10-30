package rulespec

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Reserved keys in a language set. Neither is a file language, and no rule lists
// them in applies_to.
const (
	// LangUnknown marks a changed file whose format is not recognized. It keeps
	// every rule (LEO-715).
	LangUnknown = "unknown"
	// LangNoCode marks a change in which EVERY file belongs to a non-code class.
	// Only then are application-code rules dropped: Terraform beside a Python
	// handler still gets sql-injection for the handler.
	LangNoCode = "no-code"
)

// File classes that are not application code. A non-code file carries its class as
// a token next to its language, so `applies_to: [iac]` and `applies_to_non_code:
// [iac]` both work. Every other recognized file is code.
//
// Shell, SQL, HTML and Dockerfiles are deliberately code: a script, a migration, a
// template or a RUN line can carry the injection and traversal flaws the code rules
// look for, and prod findings on them confirm it. YAML that is neither IaC nor CI
// (Compose, Ansible, Spring config) also stays code for now.
//
// Prose and stylesheets have no class: pathgate.InertReason drops them by name in
// both the plugin gate and the PR lane, so they never reach rule selection. MDX,
// which that list leaves in, holds JSX and stays unknown.
const (
	ClassIaC    = "iac"
	ClassCI     = "ci"
	ClassConfig = "config"
)

// NonCodeClasses lists every non-code class, for validating applies_to_non_code.
var NonCodeClasses = []string{ClassIaC, ClassCI, ClassConfig}

// langClass maps a language token to its non-code class.
var langClass = map[string]string{
	"terraform": ClassIaC, "hcl": ClassIaC, "bicep": ClassIaC,
	"cloudformation": ClassIaC, "arm": ClassIaC, "kubernetes": ClassIaC,
	"json": ClassConfig,
	"ci":   ClassCI,
}

var nonCode = map[string]bool{ClassIaC: true, ClassCI: true, ClassConfig: true}

// IsNonCodeClass reports whether a token is a non-code class.
func IsNonCodeClass(token string) bool { return nonCode[token] }

// File is a changed file as language detection sees it. Content may be empty, in
// which case only the path is used.
type File struct {
	Path    string
	Content string
}

// sniffBytes bounds how much of a file the content checks read. Every marker they
// look for sits in a template's or manifest's first lines.
const sniffBytes = 64 << 10

var (
	cfnYAMLVersion = regexp.MustCompile(`(?m)^AWSTemplateFormatVersion\s*:`)
	cfnYAMLRes     = regexp.MustCompile(`(?m)^Resources\s*:`)
	cfnYAMLType    = regexp.MustCompile(`(?m)^\s+Type\s*:\s*['"]?(AWS|Alexa)::\w+::`)
	cfnJSONVersion = regexp.MustCompile(`"AWSTemplateFormatVersion"\s*:`)
	cfnJSONRes     = regexp.MustCompile(`"Resources"\s*:`)
	cfnJSONType    = regexp.MustCompile(`"Type"\s*:\s*"(AWS|Alexa)::\w+::`)
	armSchema      = regexp.MustCompile(`"\$schema"\s*:\s*"https?://schema\.management\.azure\.com/schemas/[^"]*deployment(Template|Parameters)\.json`)
	k8sAPIVersion  = regexp.MustCompile(`(?m)^apiVersion\s*:\s*\S`)
	k8sKind        = regexp.MustCompile(`(?m)^kind\s*:\s*['"]?[A-Z]\w*`)
	k8sJSONVersion = regexp.MustCompile(`"apiVersion"\s*:\s*"[^"]+"`)
	k8sJSONKind    = regexp.MustCompile(`"kind"\s*:\s*"[A-Z]\w*"`)

	// embeddedCode marks executable source written inside an IaC or CI file: a
	// CloudFormation Lambda's ZipFile, a SAM function's InlineCode, an
	// actions/github-script step, a Terraform archive_file built from inline content,
	// a CloudFront function. Such a file is not declarative: it does not count towards
	// LangNoCode, and since the embedded language is not known it also adds
	// LangUnknown, which keeps every rule, language-scoped ones included.
	embeddedCode = regexp.MustCompile(`(?m)^\s*(ZipFile|InlineCode)\s*:|"(ZipFile|InlineCode)"\s*:|actions/github-script@|data\s+"archive_file"|resource\s+"aws_cloudfront_function"`)
)

// LanguagesOfFile returns a file's tokens: its language, a more specific format the
// content or path shows, and its non-code class if it has one.
//
//   - .yaml/.yml: a CI pipeline (by path) adds `ci`, CloudFormation or SAM adds
//     `cloudformation`, and a Kubernetes manifest (top-level apiVersion and kind,
//     which covers Helm templates and Kustomize) adds `kubernetes`. `yaml` stays, so
//     yaml-scoped rules still see the file.
//   - .json/.template: CloudFormation becomes `cloudformation` and an Azure Resource
//     Manager template becomes `arm`. A Kubernetes manifest (apiVersion and kind)
//     adds `kubernetes` and keeps `json`. Other .json is `json`, class config; other
//     .template stays unknown.
func LanguagesOfFile(path, content string) []string {
	lang := LanguageOf(path)
	if len(content) > sniffBytes {
		content = content[:sniffBytes]
	}
	ext := strings.ToLower(filepath.Ext(path))
	tokens := []string{lang}
	switch {
	case lang == "yaml" && isCIPath(path):
		tokens = []string{"yaml", "ci"}
	case lang == "yaml" && isCloudFormationYAML(content):
		tokens = []string{"yaml", "cloudformation"}
	case lang == "yaml" && k8sAPIVersion.MatchString(content) && k8sKind.MatchString(content):
		tokens = []string{"yaml", "kubernetes"}
	case (lang == "json" || ext == ".template") && content != "":
		if isCloudFormationJSON(content) || (ext == ".template" && isCloudFormationYAML(content)) {
			tokens = []string{"cloudformation"}
		} else if armSchema.MatchString(content) {
			tokens = []string{"arm"}
		} else if lang == "json" && k8sJSONVersion.MatchString(content) && k8sJSONKind.MatchString(content) {
			tokens = []string{"json", "kubernetes"}
		}
	}
	// The most specific token decides the class: Kubernetes JSON is iac, not config.
	for i := len(tokens) - 1; i >= 0; i-- {
		if c := langClass[tokens[i]]; c != "" && c != tokens[i] {
			return append(tokens, c)
		}
	}
	return tokens
}

// isCIPath reports whether a YAML path is a CI pipeline definition.
func isCIPath(path string) bool {
	p := "/" + strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(p)
	return strings.Contains(p, "/.github/workflows/") ||
		(strings.Contains(p, "/.github/actions/") && (base == "action.yml" || base == "action.yaml")) ||
		base == ".gitlab-ci.yml" || strings.Contains(p, "/.gitlab/ci/") ||
		strings.Contains(p, "/.circleci/") ||
		base == "azure-pipelines.yml" || base == "azure-pipelines.yaml" ||
		base == "bitbucket-pipelines.yml" ||
		strings.Contains(p, "/.buildkite/")
}

func isCloudFormationYAML(s string) bool {
	return cfnYAMLVersion.MatchString(s) || (cfnYAMLRes.MatchString(s) && cfnYAMLType.MatchString(s))
}

func isCloudFormationJSON(s string) bool {
	return cfnJSONVersion.MatchString(s) || (cfnJSONRes.MatchString(s) && cfnJSONType.MatchString(s))
}

// LanguagesOfFiles returns the language set of a change: every file's tokens, plus
// LangNoCode when every file belongs to a non-code class and embeds no code. An
// unknown file is not classed, so it both keeps every rule and clears LangNoCode. A
// file with embedded code is treated the same way, through LangUnknown.
func LanguagesOfFiles(files []File) map[string]bool {
	langs := map[string]bool{}
	noCodeOnly := len(files) > 0
	for _, f := range files {
		classed := false
		for _, l := range LanguagesOfFile(f.Path, f.Content) {
			langs[l] = true
			classed = classed || nonCode[l]
		}
		// The whole file, not the sniff window: inline code can sit anywhere. Its
		// language is not detected, so every rule stays a candidate (LEO-245 review).
		hasEmbeddedCode := embeddedCode.MatchString(f.Content)
		if hasEmbeddedCode {
			langs[LangUnknown] = true
		}
		noCodeOnly = noCodeOnly && classed && !hasEmbeddedCode
	}
	if noCodeOnly {
		langs[LangNoCode] = true
	}
	return langs
}
