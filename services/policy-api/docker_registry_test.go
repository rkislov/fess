package main

import "testing"

func TestParseImageRefAndRegistryRewrite(t *testing.T) {
	t.Setenv("FENCE_REGISTRY", "85.137.24.140:5000")
	t.Setenv("FENCE_IMAGE_TAG", "latest")

	cases := []struct {
		in, repo, tag, update string
	}{
		{"postgres:15", "library/postgres", "15", "85.137.24.140:5000/library/postgres:15"},
		{"redis:7", "library/redis", "7", "85.137.24.140:5000/library/redis:7"},
		{"opencloudeu/clamav-icap:latest", "opencloudeu/clamav-icap", "latest", "85.137.24.140:5000/opencloudeu/clamav-icap:latest"},
		{"fess/policy-api:local", "fess/policy-api", "latest", "85.137.24.140:5000/fess/policy-api:latest"},
		{"85.137.24.140:5000/fess/waf-gateway:latest", "fess/waf-gateway", "latest", "85.137.24.140:5000/fess/waf-gateway:latest"},
		{"85.137.24.140:5000/library/postgres:15", "library/postgres", "15", "85.137.24.140:5000/library/postgres:15"},
	}
	for _, c := range cases {
		repo, tag := registryRepoAndTag(c.in)
		if repo != c.repo || tag != c.tag {
			t.Errorf("%s: repo/tag %s:%s want %s:%s", c.in, repo, tag, c.repo, c.tag)
		}
		if got := updateImageName(c.in); got != c.update {
			t.Errorf("%s: update %s want %s", c.in, got, c.update)
		}
	}
}

func TestDigestFromRepoDigests(t *testing.T) {
	t.Setenv("FENCE_REGISTRY", "85.137.24.140:5000")
	d := digestFromRepoDigests([]string{
		"85.137.24.140:5000/fess/policy-api@sha256:abc",
		"fess/policy-api@sha256:old",
	}, "fess/policy-api")
	if d != "sha256:abc" {
		t.Fatalf("got %q", d)
	}
}
