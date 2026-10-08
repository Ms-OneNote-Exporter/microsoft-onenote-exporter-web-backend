// Package dockerapi is a minimal Docker Engine API client.
//
// It speaks HTTP over the unix socket with net/http and encoding/json, both
// stdlib, so the orchestrator keeps its zero-dependency property. It covers
// only the calls the verb set needs. Every other Engine API endpoint is
// deliberately unreachable: if a verb needs something new, it gets added here,
// with its own reasoning, rather than opened up through a generic passthrough.
package dockerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// maxErrorBody caps how much of a failed Engine response we read. The Engine's
// errors are short; anything longer is a daemon misbehaving and we do not need
// all of it.
const maxErrorBody = 4 << 10

// Client is a Docker Engine API client bound to one socket.
type Client struct {
	http     *http.Client
	sockPath string // for error messages only; requests go over the socket
}

// New returns a client for the socket at sockPath.
//
// The transport dials the unix socket directly and sends Host: localhost,
// which is what the Engine expects: it routes on the Host header, so a request
// arriving with any other Host is rejected.
func New(sockPath string, timeout time.Duration) *Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", sockPath)
		},
		DisableCompression: true,
		MaxIdleConns:       4,
	}
	return &Client{
		http:     &http.Client{Transport: transport, Timeout: timeout},
		sockPath: sockPath,
	}
}

// EngineError is a non-2xx response from the Engine.
type EngineError struct {
	Status  int
	Message string
}

func (e *EngineError) Error() string {
	return fmt.Sprintf("docker engine: %d %s", e.Status, e.Message)
}

// IsNotFound reports whether err is a 404 from the Engine. That is the normal
// answer to "does this container exist" and must not be conflated with a
// transport failure.
func IsNotFound(err error) bool {
	var ee *EngineError
	return errors.As(err, &ee) && ee.Status == http.StatusNotFound
}

// Container is the subset of the Engine's container inspect output we use.
// Everything else the Engine returns is ignored on purpose: the less of the
// container's state we model, the less a surprise from the daemon can reach us.
type Container struct {
	ID         string          `json:"Id"`
	Names      []string        `json:"Names"`
	State      ContainerState  `json:"State"`
	Config     ContainerConfig `json:"Config"`
	Labels     map[string]string
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	Mounts []Mount `json:"Mounts"`
}

// ContainerState is the Engine's container state.
type ContainerState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	ExitCode   int    `json:"ExitCode"`
	StartedAt  string `json:"StartedAt"`
	FinishedAt string `json:"FinishedAt"`
	// Health is the healthcheck's verdict. Absent entirely when the container
	// declares no healthcheck, which is why the caller reads it as a string and
	// treats "" as "no opinion" rather than as a failure.
	//
	// It is what makes "the runner is up" distinguishable from "the runner is
	// *listening*", which is the difference the claim path needs and could not
	// previously observe at all.
	Health ContainerHealth `json:"Health"`
}

// ContainerHealth is the Engine's record of a container's healthcheck.
type ContainerHealth struct {
	Status string `json:"Status"`
	// FailingStreak is how many consecutive checks failed. It is what turns
	// "unhealthy" into a bounded wait rather than an immediate give-up: a runner
	// inside its retries is not yet known to be broken.
	FailingStreak int `json:"FailingStreak"`
}

// ContainerConfig carries the image and the labels we reconcile against.
type ContainerConfig struct {
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

// Mount is one bind mount on a container.
type Mount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

// CreateRequest is the body of POST /containers/create.
//
// Every field is set by orchestrator code from its own config or from
// validated identifiers. Nothing in this struct is ever populated from a
// request body, which is what makes T-X3 checkable by reading this type.
type CreateRequest struct {
	Image      string            `json:"Image"`
	Entrypoint []string          `json:"Entrypoint"`
	Cmd        []string          `json:"Cmd"`
	Env        []string          `json:"Env"`
	Labels     map[string]string `json:"Labels"`
	User       string            `json:"User"`
	WorkingDir string            `json:"WorkingDir"`
	HostConfig CreateHostConfig  `json:"HostConfig"`
	// Mounts is the typed mount list. It is NOT serialised as `Mounts`: the Engine
	// **ignores a top-level `Mounts` field** on `POST /containers/create`, so a
	// request that set only this produced a container with no mounts whatsoever —
	// no vault, no artifact tree, no bearer token — and the runner exited 1 with
	// `MSOUT_RUNNER_TOKEN_FILE could not be read at /run/secrets/runner_token:
	// ENOENT`.
	//
	// Found on the first real deployment that created a runner. Every unit test
	// passed, because the tests assert against the request *struct*, and the struct
	// was correct — the wire format was not.
	//
	// It is populated rather than removed, because it is the only representation of
	// a mount where ReadOnly is a bool instead of a mode parsed out of a string.
	// CreateContainer copies it into HostConfig.Binds, which is the field the
	// Engine reads.
	Mounts       []CreateMount        `json:"-"`
	Networking   *NetworkingConfig    `json:"NetworkingConfig,omitempty"`
	StopConfig   *StopContainerConfig `json:"StopConfig,omitempty"`
	HealthConfig *HealthConfig        `json:"Healthcheck,omitempty"`
}

// HealthConfig is the container healthcheck. A runner that has lost its
// sidecar is not idle, it is broken, and the healthcheck is how that becomes
// observable without reading logs.
type HealthConfig struct {
	Test        []string `json:"Test"`
	Interval    int64    `json:"Interval"`
	Timeout     int64    `json:"Timeout"`
	Retries     int      `json:"Retries"`
	StartPeriod int64    `json:"StartPeriod"`
}

// CreateHostConfig is the resource and security section of a create request.
//
// The security fields are the point. Read-only rootfs, cap-drop ALL,
// no-new-privileges, the PID and memory caps and the tmpfs list all live here
// and are all constants from orchestrator's own code (PLANNING/PLAN-v2.md
// §5.1). None of them is reachable from a caller.
type CreateHostConfig struct {
	NetworkMode    string            `json:"NetworkMode"`
	Init           *bool             `json:"Init"`
	ReadonlyRootfs *bool             `json:"ReadonlyRootfs"`
	ShmSize        int64             `json:"ShmSize"`
	Memory         int64             `json:"Memory"`
	MemorySwap     int64             `json:"MemorySwap"`
	NanoCpus       int64             `json:"NanoCpus"`
	PidsLimit      *int64            `json:"PidsLimit"`
	CapDrop        []string          `json:"CapDrop"`
	SecurityOpt    []string          `json:"SecurityOpt"`
	Tmpfs          map[string]string `json:"Tmpfs"`
	AutoRemove     *bool             `json:"AutoRemove"`
	RestartPolicy  RestartPolicy     `json:"RestartPolicy"`
	LogConfig      LogConfig         `json:"LogConfig"`
	// Binds carries the mount list. See CreateRequest.Mounts, which explains why
	// this exists: the Engine ignores a top-level `Mounts` field, so a create
	// request that set only that produced containers with **no mounts at all**.
	Binds []string `json:"Binds"`
}

// bindString renders one mount as a bind specification.
//
// Built from typed fields rather than by a caller concatenating a string, so the
// "no caller-influenced string in a bind specification" property this code
// originally claimed is still true — it just has to be rendered here, once, from
// values that are individually checked.
//
// `Source` and `Destination` are emitted verbatim. That is safe because every
// value reaching this point is either a constant from this component or the
// orchestrator's own configured host paths — and a `:` or `,` inside one would
// change the parse rather than being escaped, so the values that come from
// configuration are validated as absolute paths at config load.
func bindString(m CreateMount) string {
	spec := m.Source + ":" + m.Destination
	if m.ReadOnly {
		spec += ":ro"
	}
	return spec
}

// isTmpfs reports whether a mount is a tmpfs rather than a bind.
//
// A tmpfs has **no host source** — the kernel provides the memory — and it cannot
// be expressed in a bind specification. Rendering one as `":/data"` produced:
//
//	500 {"message":"invalid volume specification: ':/data'"}
//
// on the first real container creation, because idle runners mount `/data` as
// tmpfs precisely so a waiting container holds no credential-bearing path. So the
// distinction is made here, once, rather than by every caller remembering it.
//
// The test is the **type**, and deliberately not "has no source". A bind mount
// with an empty source is a misconfiguration, and inferring tmpfs from the missing
// source would convert that mistake into a plausible-looking container rather than
// refusing it. Type is what the caller actually chose.
func isTmpfs(m CreateMount) bool {
	return m.Type == "tmpfs"
}

// RestartPolicy is the Engine's restart policy. Always "no": a runner that
// exits is the orchestrator's to reconcile, not the daemon's to restart,
// because a self-restarting runner would silently re-acquire its mounts.
type RestartPolicy struct {
	Name string `json:"Name"`
}

// LogConfig caps container log growth. Unbounded runner logs would be a disk
// exhaustion path on a host whose free space also gates new exports.
type LogConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

// NetworkingConfig pins the runner to exactly one network, so it is not
// reachable from the control network that api and orchestrator share.
type NetworkingConfig struct {
	EndpointsConfig map[string]*EndpointConfig `json:"EndpointsConfig"`
}

// EndpointConfig is one network attachment.
type EndpointConfig struct {
	// IPAMConfig is deliberately not set. Assigning a static address would let
	// a caller-predictable address become a mount target or a rate-limit key.
	IPAMConfig *IPAMConfig `json:"IPAMConfig,omitempty"`

	// Aliases are the DNS names the container answers to on this network.
	//
	// Added for the runner's control network, where `api` dials the runner by
	// name rather than by IP. A name derived from the slot id is stable across
	// `recycle`, which a container IP is not — so a stored address keeps
	// working when the container underneath it is replaced.
	Aliases []string `json:"Aliases,omitempty"`
}

// IPAMConfig exists only to satisfy the Engine's shape.
type IPAMConfig struct {
	IPv4Address string `json:"IPv4Address,omitempty"`
}

// StopContainerConfig bounds how long a stop may take before the daemon
// escalates to SIGKILL. A hung Chromium that ignores SIGTERM must not block a
// release forever.
type StopContainerConfig struct {
	Timeout *int `json:"Timeout,omitempty"`
}

// CreateMount is a bind mount in a create request.
type CreateMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	ReadOnly    bool   `json:"ReadOnly"`
}

// CreateResponse is the Engine's answer to create.
type CreateResponse struct {
	ID       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

// listContainer is one entry in a container list.
type listContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
}

// listResponse is the Engine's answer to a container list.
//
// A **bare array**, not an object with a `Containers` key. It was declared as the
// object, and the filter bug hid it: with `filters` rejected outright the decode was
// never reached, so the wrong shape sat there through the fix and surfaced the moment
// the filter was right —
//
//	json: cannot unmarshal array into Go value of type dockerapi.listResponse
//
// Verified against the live Engine on the deployed host rather than from the API
// reference, and `list_test.go` asserts this shape specifically. A test written
// against the same wrong struct would have agreed with the code forever.
type listResponse = []listContainer

// PingResult is the Engine's /_ping answer.
type PingResult struct {
	APIVersion string
}

// Ping checks that the daemon is reachable.
//
// The API version comes from a response header rather than the body, so this
// reads the header rather than the (plain-text, "OK") payload.
func (c *Client) Ping(ctx context.Context) (PingResult, error) {
	resp, err := c.send(ctx, http.MethodGet, "/_ping", nil)
	if err != nil {
		return PingResult{}, err
	}
	drainClose(resp.Body)
	return PingResult{APIVersion: resp.Header.Get("Api-Version")}, nil
}

// CreateContainer creates a container and returns its id. name, when non-empty,
// is a slot-derived container name; it is never caller-influenced.
func (c *Client) CreateContainer(ctx context.Context, req CreateRequest, name string) (CreateResponse, error) {
	// Copy the typed mounts into the only field the Engine reads. Done here rather
	// than by the caller so no caller can produce a container with no mounts by
	// forgetting — which is exactly what happened, and it is silent.
	//
	// tmpfs entries go to `HostConfig.Tmpfs`, which is where the Engine expects
	// them, keyed by destination. A tmpfs has no host source, so it cannot be a
	// bind at all.
	req.HostConfig.Binds = nil
	// Tmpfs is left nil unless a tmpfs mount turns up, so a request with only bind
	// mounts carries no `Tmpfs` key at all rather than an empty object.
	usedTmpfs := false
	for _, m := range req.Mounts {
		if m.Destination == "" {
			// A mount with no destination has no meaning, and rendering it would
			// produce a specification the Engine parses as something else.
			return CreateResponse{}, fmt.Errorf("mount %q has no destination", m.Source)
		}
		if !isTmpfs(m) && m.Source == "" {
			// A bind has no meaning without a host source, and rendering it would
			// produce `":/data"` — the specification the Engine rejects with
			// `500 invalid volume specification`. Refused here so the cause is the
			// caller's mount, named, rather than an opaque Engine error.
			return CreateResponse{}, fmt.Errorf(
				"bind mount %q has no source", m.Destination)
		}
		if isTmpfs(m) {
			if !usedTmpfs {
				if req.HostConfig.Tmpfs == nil {
					req.HostConfig.Tmpfs = map[string]string{}
				}
				usedTmpfs = true
			}
			// The mount's own options string, or just writable. An idle runner's
			// `/data` is tmpfs so that a waiting container holds no
			// credential-bearing path at all.
			opts := m.Source
			if opts == "" {
				opts = "rw"
			}
			req.HostConfig.Tmpfs[m.Destination] = opts
			continue
		}
		req.HostConfig.Binds = append(req.HostConfig.Binds, bindString(m))
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return CreateResponse{}, err
	}
	target := "/containers/create"
	if name != "" {
		target += "?name=" + url.PathEscape(name)
	}
	raw, err := c.request(ctx, http.MethodPost, target, payload)
	if err != nil {
		return CreateResponse{}, err
	}
	var out CreateResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return CreateResponse{}, err
	}
	return out, nil
}

// StartContainer starts a created container.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	_, err := c.request(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil)
	return err
}

// StopContainer stops a container, giving it timeout seconds to exit cleanly
// before the daemon escalates to SIGKILL. A container that is already gone is
// the outcome the caller asked for, so a 404 is not an error.
func (c *Client) StopContainer(ctx context.Context, id string, timeout int) error {
	body, err := json.Marshal(StopContainerConfig{Timeout: &timeout})
	if err != nil {
		return err
	}
	_, err = c.request(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop", body)
	if err != nil && IsNotFound(err) {
		return nil
	}
	return err
}

// RemoveContainer force-removes a container and its anonymous volumes.
//
// force=1 is required because a running container cannot otherwise be removed,
// and "remove" is exactly the verb whose job is to make it not exist. A 404
// means it is already gone.
func (c *Client) RemoveContainer(ctx context.Context, id string) error {
	err := c.requestErr(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id)+"?force=1&v=1")
	if err != nil && IsNotFound(err) {
		return nil
	}
	return err
}

// InspectContainer returns the container's state.
func (c *Client) InspectContainer(ctx context.Context, id string) (*Container, error) {
	raw, err := c.request(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return nil, err
	}
	var out Container
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	// Labels live under Config in the Engine's output. Lifting them into one
	// field keeps reconciliation code from reaching two levels deep.
	out.Labels = out.Config.Labels
	return &out, nil
}

// ListContainersByLabel returns the ids of every container carrying label,
// including stopped ones. Boot reconciliation needs the stopped ones: a
// container that died must be cleaned up, not just the running ones.
//
// **The `filters` parameter takes JSON, not a bare value.** The Engine's schema for
// it is an object of arrays:
//
//	?filters={"label":["msout.component=runner"]}
//
// It was sent as a bare, URL-escaped `label`, which the Engine rejected on every
// single boot:
//
//	reconcile: list containers: docker engine: 400 {"message":"invalid filter"}
//
// which the caller logs as "boot reconciliation failed, serving anyway" and moves on
// from. So reconciliation has never run: an orchestrator restart did not adopt its
// existing runners, and `EnsurePool` would create a *second* runner for a slot whose
// container was still alive and holding a session's vault.
//
// Encoded from the typed value rather than by hand so the shape cannot drift again —
// the same reason the mount list is rendered by one function.
func (c *Client) ListContainersByLabel(ctx context.Context, label string) ([]string, error) {
	filter, err := json.Marshal(map[string][]string{"label": {label}})
	if err != nil {
		// A []string cannot fail to marshal, so this is unreachable. Returning an
		// error rather than ignoring it keeps the signature honest if that changes.
		return nil, fmt.Errorf("encode label filter: %w", err)
	}

	query := url.Values{}
	query.Set("all", "1")
	query.Set("filters", string(filter))

	raw, err := c.request(ctx, http.MethodGet, "/containers/json?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var out listResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out))
	for _, ctr := range out {
		ids = append(ids, ctr.ID)
	}
	return ids, nil
}

// request performs a call and returns the response body on success.
func (c *Client) request(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
	resp, err := c.send(ctx, method, path, payload)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp.Body)
	return io.ReadAll(resp.Body)
}

// requestErr performs a call and discards the body, returning an error for any
// non-2xx.
func (c *Client) requestErr(ctx context.Context, method, path string, payload ...[]byte) error {
	var body []byte
	if len(payload) > 0 {
		body = payload[0]
	}
	resp, err := c.send(ctx, method, path, body)
	if err != nil {
		return err
	}
	drainClose(resp.Body)
	return nil
}

// send builds and executes the HTTP request over the unix socket.
func (c *Client) send(ctx context.Context, method, path string, payload []byte) (*http.Response, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, reader)
	if err != nil {
		return nil, err
	}
	// The Engine routes on Host and rejects anything else.
	req.Host = "localhost"
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker engine (%s): %w", c.sockPath, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer drainClose(resp.Body)
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return nil, &EngineError{Status: resp.StatusCode, Message: string(bytes.TrimSpace(raw))}
	}
	return resp, nil
}

// drainClose reads the remainder of the body before closing so the connection
// can be reused, and caps the read so a misbehaving daemon cannot make us
// buffer without limit.
func drainClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 32<<10))
	_ = rc.Close()
}
