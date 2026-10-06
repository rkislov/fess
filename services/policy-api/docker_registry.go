package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type imageRef struct {
	Host string
	Repo string
	Tag  string
}

func fenceRegistryHost() string {
	h := strings.TrimSpace(os.Getenv("FENCE_REGISTRY"))
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimRight(h, "/")
	if h == "" {
		return "85.137.24.140:5000"
	}
	return h
}

func fenceRegistryBaseURL() string {
	scheme := strings.TrimSpace(os.Getenv("FENCE_REGISTRY_SCHEME"))
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + fenceRegistryHost()
}

func fenceImageTag() string {
	t := strings.TrimSpace(os.Getenv("FENCE_IMAGE_TAG"))
	if t == "" {
		return "latest"
	}
	return t
}

func parseImageRef(image string) imageRef {
	image = strings.TrimSpace(image)
	tag := "latest"
	rest := image
	// digest form repo@sha256: is not used for pull-by-tag
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		after := rest[i+1:]
		if !strings.Contains(after, "/") {
			tag = after
			rest = rest[:i]
		}
	}
	host := ""
	repo := rest
	slash := strings.Index(rest, "/")
	if slash >= 0 {
		first := rest[:slash]
		if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
			host = first
			repo = rest[slash+1:]
		}
	}
	return imageRef{Host: host, Repo: repo, Tag: tag}
}

func registryRepoAndTag(image string) (repo, tag string) {
	ref := parseImageRef(image)
	repo = ref.Repo
	tag = ref.Tag
	reg := fenceRegistryHost()
	if ref.Host != "" && !strings.EqualFold(ref.Host, reg) {
		// foreign registry: keep path as-is
	}
	if ref.Host == "" || strings.EqualFold(ref.Host, reg) {
		if !strings.Contains(repo, "/") {
			repo = "library/" + repo
		}
	}
	if ref.Host == "" && strings.HasPrefix(repo, "fess/") && (tag == "local" || tag == "") {
		tag = fenceImageTag()
	}
	if tag == "local" && strings.HasPrefix(repo, "fess/") {
		tag = fenceImageTag()
	}
	if tag == "" {
		tag = "latest"
	}
	return repo, tag
}

func updateImageName(image string) string {
	repo, tag := registryRepoAndTag(image)
	return fenceRegistryHost() + "/" + repo + ":" + tag
}

func digestFromRepoDigests(digests []string, wantRepo string) string {
	reg := fenceRegistryHost()
	prefix := reg + "/" + wantRepo + "@"
	for _, d := range digests {
		if strings.HasPrefix(d, prefix) {
			if i := strings.Index(d, "@"); i >= 0 {
				return d[i+1:]
			}
		}
	}
	for _, d := range digests {
		if i := strings.Index(d, "@"); i >= 0 {
			return d[i+1:]
		}
	}
	return ""
}

func fetchRegistryDigest(ctx context.Context, repo, tag string) (string, error) {
	u := fenceRegistryBaseURL() + "/v2/" + repo + "/manifests/" + url.PathEscape(tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))
	cli := &http.Client{Timeout: 4 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry %s: HTTP %d", repo, resp.StatusCode)
	}
	d := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	if d == "" {
		return "", fmt.Errorf("registry %s: no digest header", repo)
	}
	return d, nil
}

type dockerImageInspect struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
	RepoTags    []string `json:"RepoTags"`
}

func inspectDockerImage(ctx context.Context, cli *http.Client, image string) (dockerImageInspect, error) {
	var out dockerImageInspect
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/images/"+image+"/json", nil)
	if err != nil {
		return out, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return out, fmt.Errorf("image inspect %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}
