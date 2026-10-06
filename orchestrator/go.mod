// The orchestrator has ZERO third-party dependencies, on purpose.
//
// It is the only holder of /var/run/docker.sock, so its security argument is
// "these ~1k lines have no bugs" plus "nothing a caller sends reaches a
// dangerous operation" (PLANNING/PLAN-v3.md §2.1). The second half of that
// argument is only auditable if there is no transitive tree to audit. The
// Docker Engine API is HTTP over a unix socket, so net/http plus a custom
// dialer covers everything; everything else needed is stdlib.
//
// Adding a require block here needs a line in PLANNING/PLAN-v3.md explaining
// why the audit surface grew.
module github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator

go 1.25