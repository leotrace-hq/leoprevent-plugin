package gate

import (
	"slices"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
	"github.com/leotrace-hq/leoprevent-plugin/rulespec"
)

// These IaC and other non-code source formats must survive the plugin gate and carry the language tokens
// the server routes rules on (LEO-245). Reaching review is separate from the selector
// choosing an applicable rule; docs/file-class-routing.md is the inventory.
func TestIaCSourceFormatsReachReview(t *testing.T) {
	cases := []struct {
		path, content string
		langs         []string
	}{
		{"infra/main.tf", `resource "aws_s3_bucket" "data" { bucket = "example-data" }`, []string{"terraform", "iac"}},
		{"infra/main.tf.json", `{"resource":{"aws_s3_bucket":{"data":{"bucket":"example-data"}}}}`, []string{"terraform", "iac"}},
		{"infra/terragrunt.hcl", `terraform { source = "../modules/network" }`, []string{"hcl", "iac"}},
		{"infra/index.ts", `const bucket = new aws.s3.Bucket("data");`, []string{"typescript"}},
		{"infra/main.py", `bucket = aws.s3.Bucket("data")`, []string{"python"}},
		{"infra/Pulumi.yaml", "name: infrastructure\nruntime: yaml\nresources: {}", []string{"yaml"}},
		{"infra/cloudformation.yaml", "Resources:\n  Data:\n    Type: AWS::S3::Bucket", []string{"yaml", "cloudformation", "iac"}},
		{"infra/cloudformation.json", `{"Resources":{"Data":{"Type":"AWS::S3::Bucket"}}}`, []string{"cloudformation", "iac"}},
		{"infra/cloudformation.template", `{"AWSTemplateFormatVersion":"2010-09-09","Resources":{}}`, []string{"cloudformation", "iac"}},
		{"sam/template.yaml", "Transform: AWS::Serverless-2016-10-31\nResources:\n  Fn:\n    Type: AWS::Serverless::Function", []string{"yaml", "cloudformation", "iac"}},
		{"infra/main.bicep", "resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {\n name: 'example'\n}", []string{"bicep", "iac"}},
		{"infra/main.bicepparam", "using './main.bicep'\nparam location = 'westeurope'", []string{"bicep", "iac"}},
		{"infra/azuredeploy.json", `{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","resources":[]}`, []string{"arm", "iac"}},
		{"k8s/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app", []string{"yaml", "kubernetes", "iac"}},
		{"charts/app/templates/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}", []string{"yaml", "kubernetes", "iac"}},
		{"overlays/prod/kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - ../../base", []string{"yaml", "kubernetes", "iac"}},
		{"Dockerfile", "FROM alpine:3.20\nUSER root", []string{"dockerfile"}},
		{"compose.yml", "services:\n  app:\n    image: nginx", []string{"yaml"}},
		{"ansible/site.yml", "- hosts: all\n  tasks:\n    - command: whoami", []string{"yaml"}},
		// Other non-code classes (LEO-245). Prose and stylesheets never get here: the
		// gate drops them as inert, so they have no class.
		{".github/workflows/ci.yml", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest", []string{"yaml", "ci"}},
		{"package.json", `{"name":"app","scripts":{"build":"tsc"}}`, []string{"json", "config"}},
		// Formats without a mapping stay unknown, which keeps every rule (LEO-715).
		{"charts/app/templates/_helpers.tpl", `{{- define "app.name" -}}app{{- end -}}`, []string{"unknown"}},
		{"puppet/manifests/site.pp", "package { 'nginx': ensure => installed }", []string{"unknown"}},
		{"fly.toml", "app = \"example\"\n[http_service]\nforce_https = false", []string{"unknown"}},
		{"policy/access.rego", "package access\ndefault allow := false", []string{"unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if pathgate.IsSecretPath(tc.path) {
				t.Fatal("source unexpectedly excluded as a secret path")
			}
			changes := []transcript.Change{{FilePath: tc.path, AddedText: tc.content, FullContent: tc.content}}
			if len(Run(changes)) != 1 {
				t.Fatal("source did not reach review")
			}
			if got := rulespec.LanguagesOfFile(tc.path, tc.content); !slices.Equal(got, tc.langs) {
				t.Fatalf("languages = %v, want %v; update docs/file-class-routing.md with intentional mappings", got, tc.langs)
			}
		})
	}
}
