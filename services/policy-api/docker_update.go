package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"fence/pkg/auth"
)

var dockerUpdateMu sync.Mutex

type containerUpdateResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Service string `json:"service"`
	Image   string `json:"image"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

type containerUpdateResponse struct {
	OK      bool                     `json:"ok"`
	Message string                   `json:"message,omitempty"`
	Results []containerUpdateResult  `json:"results"`
}

func dashboardContainersHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/dashboard/containers")
	path = strings.Trim(path, "/")
	switch {
	case path == "update-all" && r.Method == http.MethodPost:
		updateContainersHandler(w, r, true, "")
	case strings.HasSuffix(path, "/update") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(path, "/update")
		id = strings.Trim(id, "/")
		updateContainersHandler(w, r, false, id)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func updateContainersHandler(w http.ResponseWriter, r *http.Request, all bool, id string) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return
	}
	if !dockerUpdateMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "уже выполняется обновление контейнеров"})
		return
	}

	health := collectDockerHealth(r.Context())
	if !health.Available {
		dockerUpdateMu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": health.Error})
		return
	}

	var targets []containerHealth
	if all {
		targets = health.Containers
	} else {
		found := false
		for _, c := range health.Containers {
			if c.ID == id || c.Name == id || c.Service == id {
				targets = append(targets, c)
				found = true
				break
			}
		}
		if !found {
			dockerUpdateMu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "контейнер не найден"})
			return
		}
	}

	self := false
	hn, _ := os.Hostname()
	for _, c := range targets {
		if isSelfContainer(hn, c) {
			self = true
			break
		}
	}

	run := func() containerUpdateResponse {
		defer dockerUpdateMu.Unlock()
		out := containerUpdateResponse{OK: true, Results: []containerUpdateResult{}}
		// policy-api last so the process can finish other pulls first
		var last *containerHealth
		ordered := make([]containerHealth, 0, len(targets))
		for i := range targets {
			if isSelfContainer(hn, targets[i]) {
				cp := targets[i]
				last = &cp
				continue
			}
			ordered = append(ordered, targets[i])
		}
		if last != nil {
			ordered = append(ordered, *last)
		}
		for _, c := range ordered {
			res := containerUpdateResult{ID: c.ID, Name: c.Name, Service: c.Service, Image: c.UpdateImage}
			if strings.TrimSpace(c.UpdateImage) == "" {
				res.Status = "skipped"
				res.Error = "нет образа registry"
				out.Results = append(out.Results, res)
				continue
			}
			if !c.UpdateAvailable {
				res.Status = "skipped"
				out.Results = append(out.Results, res)
				continue
			}
			if err := pullAndRecreateContainer(context.Background(), c); err != nil {
				res.Status = "error"
				res.Error = err.Error()
				out.OK = false
			} else {
				res.Status = "updated"
			}
			out.Results = append(out.Results, res)
		}
		return out
	}

	if self {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(containerUpdateResponse{
			OK:      true,
			Message: "обновление запущено; контейнер policy-api будет пересоздан в конце",
		})
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		go func() { _ = run() }()
		return
	}

	writeJSON(w, http.StatusOK, run())
}

func isSelfContainer(hostname string, c containerHealth) bool {
	if hostname == "" {
		return false
	}
	if strings.EqualFold(c.Service, "policy-api") || strings.Contains(strings.ToLower(c.Name), "policy-api") {
		return true
	}
	return strings.HasPrefix(hostname, c.ID)
}

func pullAndRecreateContainer(ctx context.Context, c containerHealth) error {
	cli := dockerAPIClient(12 * time.Minute)
	fullID, inspect, err := inspectContainerByRef(ctx, cli, c)
	if err != nil {
		return err
	}
	if err := dockerPull(ctx, cli, c.UpdateImage); err != nil {
		return err
	}
	return recreateContainer(ctx, cli, fullID, inspect, c.UpdateImage)
}

func dockerAPIClient(timeout time.Duration) *http.Client {
	c := dockerHTTPClient(dockerSockPath())
	c.Timeout = timeout
	return c
}

func inspectContainerByRef(ctx context.Context, cli *http.Client, c containerHealth) (string, map[string]any, error) {
	try := []string{c.Name, c.ID}
	var last error
	for _, ref := range try {
		if ref == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/containers/"+ref+"/json", nil)
		if err != nil {
			last = err
			continue
		}
		resp, err := cli.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("inspect %s: HTTP %d", ref, resp.StatusCode)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return "", nil, err
		}
		id, _ := m["Id"].(string)
		return id, m, nil
	}
	if last == nil {
		last = fmt.Errorf("container not found")
	}
	return "", nil, last
}

func dockerPull(ctx context.Context, cli *http.Client, image string) error {
	ref := parseImageRef(image)
	from := image
	if ref.Tag != "" && strings.HasSuffix(image, ":"+ref.Tag) {
		from = strings.TrimSuffix(image, ":"+ref.Tag)
	}
	q := url.Values{}
	q.Set("fromImage", from)
	q.Set("tag", ref.Tag)
	u := "http://localhost/images/create?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("pull %s: %w", image, err)
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var lastErr string
	for {
		var msg map[string]any
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				break
			}
			break
		}
		if e, ok := msg["error"].(string); ok && e != "" {
			lastErr = e
		}
	}
	if resp.StatusCode != http.StatusOK {
		if lastErr == "" {
			lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("pull %s: %s", image, lastErr)
	}
	if lastErr != "" {
		return fmt.Errorf("pull %s: %s", image, lastErr)
	}
	return nil
}

func recreateContainer(ctx context.Context, cli *http.Client, fullID string, inspect map[string]any, newImage string) error {
	name, _ := inspect["Name"].(string)
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		return fmt.Errorf("container has no name")
	}
	cfg, _ := inspect["Config"].(map[string]any)
	if cfg == nil {
		return fmt.Errorf("inspect missing Config")
	}
	cfg["Image"] = newImage
	host, _ := inspect["HostConfig"]
	networks := map[string]any{}
	if ns, ok := inspect["NetworkSettings"].(map[string]any); ok {
		if n, ok := ns["Networks"].(map[string]any); ok {
			networks = n
		}
	}
	createBody := map[string]any{
		"Hostname":         cfg["Hostname"],
		"Domainname":       cfg["Domainname"],
		"User":             cfg["User"],
		"Env":              cfg["Env"],
		"Cmd":              cfg["Cmd"],
		"Entrypoint":       cfg["Entrypoint"],
		"Image":            newImage,
		"Labels":           cfg["Labels"],
		"WorkingDir":       cfg["WorkingDir"],
		"ExposedPorts":     cfg["ExposedPorts"],
		"Tty":              cfg["Tty"],
		"OpenStdin":        cfg["OpenStdin"],
		"HostConfig":       host,
		"NetworkingConfig": map[string]any{"EndpointsConfig": networks},
	}
	raw, err := json.Marshal(createBody)
	if err != nil {
		return err
	}

	oldName := name + "-old-" + shortID(fullID)
	if err := dockerPost(ctx, cli, "http://localhost/containers/"+fullID+"/stop?t=20", nil); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	if err := dockerPost(ctx, cli, "http://localhost/containers/"+fullID+"/rename?name="+oldName, nil); err != nil {
		_ = dockerPost(ctx, cli, "http://localhost/containers/"+fullID+"/start", nil)
		return fmt.Errorf("rename: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/containers/create?name="+name, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		_ = dockerPost(ctx, cli, "http://localhost/containers/"+fullID+"/rename?name="+name, nil)
		_ = dockerPost(ctx, cli, "http://localhost/containers/"+fullID+"/start", nil)
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		_ = dockerPost(ctx, cli, "http://localhost/containers/"+fullID+"/rename?name="+name, nil)
		_ = dockerPost(ctx, cli, "http://localhost/containers/"+fullID+"/start", nil)
		return fmt.Errorf("create: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var created struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal(body, &created)
	newID := created.ID
	if newID == "" {
		newID = name
	}
	if err := dockerPost(ctx, cli, "http://localhost/containers/"+newID+"/start", nil); err != nil {
		return fmt.Errorf("start new: %w (старый контейнер: %s)", err, oldName)
	}
	_ = dockerDelete(ctx, cli, "http://localhost/containers/"+fullID+"?v=false")
	return nil
}

func dockerPost(ctx context.Context, cli *http.Client, url string, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func dockerDelete(ctx context.Context, cli *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
