package rulespec

import (
	"slices"
	"testing"
)

const (
	cfnYAML = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"
	samYAML = "Transform: AWS::Serverless-2016-10-31\nResources:\n  Fn:\n    Type: AWS::Serverless::Function\n"
	cfnJSON = `{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`
	armJSON = `{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","resources":[]}`
	k8sYAML = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n"
	helmTpl = "{{- if .Values.enabled }}\napiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Release.Name }}\n{{- end }}\n"
	ghaYAML = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
)

func TestLanguagesOfFile(t *testing.T) {
	cases := []struct {
		path, content string
		want          []string
	}{
		{"infra/main.tf", `resource "aws_s3_bucket" "b" {}`, []string{"terraform", "iac"}},
		{"template.yaml", cfnYAML, []string{"yaml", "cloudformation", "iac"}},
		{"sam/template.yml", samYAML, []string{"yaml", "cloudformation", "iac"}},
		{"stack.json", cfnJSON, []string{"cloudformation", "iac"}},
		{"stack.template", cfnJSON, []string{"cloudformation", "iac"}},
		{"stack.template", cfnYAML, []string{"cloudformation", "iac"}},
		{"azuredeploy.json", armJSON, []string{"arm", "iac"}},
		{"k8s/deployment.yaml", k8sYAML, []string{"yaml", "kubernetes", "iac"}},
		{"charts/app/templates/service.yaml", helmTpl, []string{"yaml", "kubernetes", "iac"}},
		// CI pipelines, by path.
		{".github/workflows/ci.yml", ghaYAML, []string{"yaml", "ci"}},
		{"svc/.github/actions/setup/action.yml", "runs:\n  using: composite\n", []string{"yaml", "ci"}},
		{".gitlab-ci.yml", "build:\n  script: make\n", []string{"yaml", "ci"}},
		{".circleci/config.yml", "version: 2.1\n", []string{"yaml", "ci"}},
		{"azure-pipelines.yml", "trigger: [main]\n", []string{"yaml", "ci"}},
		// Kubernetes written as JSON is iac, not config, and keeps json.
		{"k8s/rbac.json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","rules":[]}`, []string{"json", "kubernetes", "iac"}},
		// Config.
		{"package.json", `{"name":"app","dependencies":{}}`, []string{"json", "config"}},
		{"tsconfig.json", "", []string{"json", "config"}},
		// Still code, or still unclassed YAML.
		{"config/settings.yaml", "Resources:\n  limit: 3\n", []string{"yaml"}},
		{"compose.yml", "services:\n  app:\n    image: nginx\n", []string{"yaml"}},
		{"migrations/001.sql", "create table t (id int);", []string{"sql"}},
		{"deploy.sh", "make", []string{"shell"}},
		{"app.py", "kind: Deployment", []string{"python"}},
		// No content: the path decides.
		{"k8s/deployment.yaml", "", []string{"yaml"}},
		{"notes.txt", "", []string{"unknown"}},
		// MDX holds JSX, so it is not prose: unknown keeps every rule.
		{"docs/guide.mdx", "import X from './x'\n<X />", []string{"unknown"}},
	}
	for _, tc := range cases {
		if got := LanguagesOfFile(tc.path, tc.content); !slices.Equal(got, tc.want) {
			t.Errorf("LanguagesOfFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// The ask behind LEO-245: an application-code rule such as sql-injection has
// nothing to review in a change made only of non-code files, while a rule that opts
// into one of the change's classes, and a scoped rule naming it, still reach the
// selector.
func TestNoCodeChangeDropsApplicationRules(t *testing.T) {
	rules := []Rule{
		{ID: "sql-injection"},
		{ID: "hardcoded-secrets", AppliesToNonCode: []string{"iac", "ci", "config"}},
		{ID: "config-driven-auth-bypass", AppliesToNonCode: []string{"config"}},
		{ID: "cloud-iam-over-grant", AppliesTo: []string{"iac", "yaml", "json"}},
		{ID: "k8s-rbac-over-grant", AppliesTo: []string{"yaml"}},
		{ID: "xss-frontend", AppliesTo: []string{"javascript", "typescript", "html"}},
	}
	ids := func(files ...File) []string {
		var out []string
		for _, r := range FilterByLangs(rules, LanguagesOfFiles(files)) {
			out = append(out, r.ID)
		}
		return out
	}
	tf := File{"infra/iam.tf", `resource "aws_iam_role" "r" {}`}
	cfn := File{"template.yaml", cfnYAML}
	k8s := File{"k8s/rbac.yaml", "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"}
	arm := File{"azuredeploy.json", armJSON}
	gha := File{".github/workflows/ci.yml", ghaYAML}
	pkg := File{"package.json", `{"name":"app"}`}
	py := File{"app.py", "x = 1"}

	for _, tc := range []struct {
		name  string
		files []File
		want  []string
	}{
		{"terraform only", []File{tf}, []string{"hardcoded-secrets", "cloud-iam-over-grant"}},
		{"cloudformation yaml only", []File{cfn}, []string{"hardcoded-secrets", "cloud-iam-over-grant", "k8s-rbac-over-grant"}},
		{"kubernetes only", []File{k8s}, []string{"hardcoded-secrets", "cloud-iam-over-grant", "k8s-rbac-over-grant"}},
		{"arm only", []File{arm}, []string{"hardcoded-secrets", "cloud-iam-over-grant"}},
		{"workflow only", []File{gha}, []string{"hardcoded-secrets", "cloud-iam-over-grant", "k8s-rbac-over-grant"}},
		{"package.json only", []File{pkg}, []string{"hardcoded-secrets", "config-driven-auth-bypass", "cloud-iam-over-grant"}},
		{"terraform + package.json", []File{tf, pkg}, []string{"hardcoded-secrets", "config-driven-auth-bypass", "cloud-iam-over-grant"}},
		// Application code beside them brings the application rules back.
		{"terraform + python", []File{tf, py}, []string{"sql-injection", "hardcoded-secrets", "config-driven-auth-bypass", "cloud-iam-over-grant"}},
		{"compose yaml", []File{{"compose.yml", "services: {}"}}, []string{"sql-injection", "hardcoded-secrets", "config-driven-auth-bypass", "cloud-iam-over-grant", "k8s-rbac-over-grant"}},
		// An unknown format keeps everything (LEO-715).
		{"terraform + unknown", []File{tf, {"fly.toml", "app = \"x\""}}, []string{"sql-injection", "hardcoded-secrets", "config-driven-auth-bypass", "cloud-iam-over-grant", "k8s-rbac-over-grant", "xss-frontend"}},
		{"python only", []File{py}, []string{"sql-injection", "hardcoded-secrets", "config-driven-auth-bypass"}},
	} {
		if got := ids(tc.files...); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Code written inside an IaC or CI file is still code: the file does not count
// towards LangNoCode, so the change keeps its application-code rules (LEO-245 review).
func TestEmbeddedCodeKeepsApplicationRules(t *testing.T) {
	cmdi := Rule{ID: "os-command-injection"}
	// A language-scoped rule must survive too: the embedded language is not known.
	proto := Rule{ID: "prototype-pollution", AppliesTo: []string{"javascript", "typescript"}}
	for _, f := range []File{
		{"template.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Fn:\n    Type: AWS::Lambda::Function\n    Properties:\n      Code:\n        ZipFile: |\n          import os\n"},
		{"stack.json", `{"AWSTemplateFormatVersion":"2010-09-09","Resources":{"Fn":{"Type":"AWS::Lambda::Function","Properties":{"Code":{"ZipFile":"import os"}}}}}`},
		{"sam/template.yaml", "Transform: AWS::Serverless-2016-10-31\nResources:\n  Fn:\n    Type: AWS::Serverless::Function\n    Properties:\n      InlineCode: |\n        exports.handler = async () => {}\n"},
		{".github/workflows/triage.yml", "on: issues\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: |\n            github.rest.issues.addLabels({})\n"},
		{"lambda.tf", "data \"archive_file\" \"fn\" {\n  type = \"zip\"\n  source {\n    content  = \"import os\"\n    filename = \"index.py\"\n  }\n}\n"},
		{"edge.tf", "resource \"aws_cloudfront_function\" \"rewrite\" {\n  code = \"function handler(event) { return event.request }\"\n}\n"},
	} {
		langs := LanguagesOfFiles([]File{f})
		if langs[LangNoCode] || !cmdi.AppliesToLangs(langs) || !proto.AppliesToLangs(langs) {
			t.Errorf("%s: embedded code lost the application rules: %v", f.Path, langs)
		}
	}
	// A declarative template and an ordinary workflow stay no-code.
	for _, f := range []File{
		{"template.yaml", cfnYAML},
		{".github/workflows/ci.yml", ghaYAML},
		{"iam.tf", `resource "aws_iam_role" "r" {}`},
	} {
		langs := LanguagesOfFiles([]File{f})
		if !langs[LangNoCode] || langs[LangUnknown] || proto.AppliesToLangs(langs) {
			t.Errorf("%s: declarative file was not narrowed: %v", f.Path, langs)
		}
	}
}

// Unknown formats must not lose candidates merely because a recognized file was
// changed alongside them (LEO-715). Pin both orders and the post-selection filter.
func TestMixedUnknownLanguagesKeepCandidates(t *testing.T) {
	rules := []Rule{
		{ID: "generic"},
		{ID: "yaml-policy", AppliesTo: []string{"yaml"}},
		{ID: "terraform-policy", AppliesTo: []string{"terraform"}},
	}
	for _, unknown := range []string{"fly.toml", "site.pp", "web.sls", "_helpers.tpl", "access.rego", "access.sentinel", "notes.txt", "future.unknown", "no-extension"} {
		for _, known := range []string{"app.py", "deploy.sh", "main.tf", "package.json", "README.md"} {
			for _, paths := range [][]string{{unknown, known}, {known, unknown}} {
				if got := FilterByLanguages(rules, paths); len(got) != len(rules) {
					t.Errorf("%v: kept %d rules, want %d", paths, len(got), len(rules))
				}
			}
		}
	}
}

func TestParseRulesAppliesToNonCode(t *testing.T) {
	rules, err := ParseRules([]byte("- id: secrets\n  type: pattern\n  applies_to_non_code: [iac, ci]\n- id: sqli\n  type: pattern\n"), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rules[0].AppliesToNonCode, []string{"iac", "ci"}) || rules[1].AppliesToNonCode != nil {
		t.Fatalf("applies_to_non_code did not round-trip: %+v", rules)
	}
}

func TestNonCodeClassesAreClassTokens(t *testing.T) {
	for _, c := range NonCodeClasses {
		if !IsNonCodeClass(c) {
			t.Errorf("%s listed but not a non-code class", c)
		}
	}
	if IsNonCodeClass("yaml") || IsNonCodeClass(LangUnknown) {
		t.Error("yaml and unknown must not be non-code classes")
	}
}
