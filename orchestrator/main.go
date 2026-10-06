// Command orchestrator is the only holder of /var/run/docker.sock.
//
// It serves a fixed verb set — claim, release, recycle, remove, stat — to `api`
// on an internal network, and nothing else. See PLANNING/PLAN-v3.md §2.1 for why
// it is a separate process from `api`, and orchestrator/README.md for why it is
// written in Go with zero third-party dependencies.
//
// It refuses to start without its HMAC secret rather than serving open, because
// an unauthenticated orchestrator is an unauthenticated container spawner on the
// host.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/dockerapi"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/pool"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/server"
)

func main() {
	if err := run(); err != nil {
		// The process exits non-zero on any fatal condition. A container
		// restart policy on the orchestrator would then surface as a crash loop
		// rather than a silently degraded pool.
		fmt.Fprintf(os.Stderr, "orchestrator: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load(os.Getenv, os.ReadFile)
	if err != nil {
		// Almost always ErrMissingSecret. Returning it rather than continuing
		// is the T-I6 requirement.
		return err
	}
	log.Info("configuration loaded",
		"listen", cfg.Listen,
		"dockerSocket", cfg.DockerSocket,
		"poolSize", cfg.PoolSize,
		"runnerImage", cfg.RunnerImage,
		"runnerNetwork", cfg.RunnerNetwork,
		"vaultRoot", cfg.VaultRoot,
		"artifactRoot", cfg.ArtifactRoot,
		"replayWindowSeconds", int(cfg.ReplayWindow.Seconds()),
	)

	// The secret is never logged, and the byte slice is not printed by any of
	// the calls above. It is held in cfg for the lifetime of the process.

	docker := dockerapi.New(cfg.DockerSocket, cfg.RequestTimeout)

	pingCtx, cancelPing := context.WithTimeout(context.Background(), cfg.RequestTimeout)
	_, err = docker.Ping(pingCtx)
	cancelPing()
	if err != nil {
		// Refusing to start without the daemon is deliberate. A pool manager
		// that cannot reach the daemon would report itself healthy and fail
		// every claim, which is worse than a container that restarts until the
		// socket is there.
		return fmt.Errorf("docker daemon unreachable: %w", err)
	}
	log.Info("docker daemon reachable")

	p := pool.New(cfg, docker, log)
	srv := server.New(cfg, p, log, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Boot reconciliation runs before the listener opens, so the first request
	// `api` makes already sees a reconciled pool. A failure here is recorded
	// and exposed on /healthz rather than being fatal: the orchestrator can
	// still serve stat and release, and refusing to start would turn a partial
	// reconciliation problem into an outage.
	reconcileCtx, cancelReconcile := context.WithTimeout(ctx, 2*cfg.RequestTimeout)
	// NeverExpire is used because `api` is not reachable yet during boot.
	// Adopting a container is the recoverable error here; deleting a live
	// session is not.
	reconcileErr := p.Reconcile(reconcileCtx, server.NeverExpire)
	cancelReconcile()
	srv.SetReconcileResult(reconcileErr)
	if reconcileErr != nil {
		log.Error("boot reconciliation failed, serving anyway", "error", reconcileErr)
	} else {
		log.Info("boot reconciliation complete", "slots", len(p.Slots()))
	}

	if err := p.EnsurePool(ctx); err != nil {
		// A pool that cannot reach its size is degraded but functional: `api`
		// will see ErrNoSlot and answer with a wait estimate. Log it loudly and
		// keep serving.
		log.Error("initial pool fill incomplete", "error", err)
	}

	httpSrv := &http.Server{
		Addr:    cfg.Listen,
		Handler: srv.Handler(),
		// Read and write deadlines apply to the internal network, where
		// requests are small and fast. They exist so a stalled caller cannot
		// hold a goroutine indefinitely.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Do not advertise the Go version. The orchestrator is not published,
		// but a version string in an error page is free reconnaissance.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	// Background ticks: pool top-up and TTL sweep. Both are idempotent.
	tickerCtx, stopTicker := context.WithCancel(ctx)
	defer stopTicker()
	go runMaintenance(tickerCtx, log, p, cfg)

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen)
		err := httpSrv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received", "grace", cfg.ShutdownGrace.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		// Report it, but do not treat a slow shutdown as a fatal error: the
		// process is exiting and the next one will reconcile.
		log.Error("graceful shutdown incomplete", "error", err)
	}
	log.Info("stopped")
	return nil
}

// runMaintenance tops the pool up and applies the TTLs on a timer.
//
// One goroutine for both, deliberately. Two would race on the same slots, and
// the lock discipline needed to make that safe is more subtle than the problem
// deserves — a pool of a few runners does not need two independent timers.
func runMaintenance(ctx context.Context, log *slog.Logger, p *pool.Pool, cfg *config.Config) {
	const (
		sweepInterval = 30 * time.Second
		poolInterval  = 10 * time.Second
	)

	poolTicker := time.NewTicker(poolInterval)
	defer poolTicker.Stop()
	sweepTicker := time.NewTicker(sweepInterval)
	defer sweepTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-poolTicker.C:
			if err := p.EnsurePool(ctx); err != nil {
				log.Warn("pool top-up failed", "error", err)
			}
		case <-sweepTicker.C:
			if err := p.Sweep(ctx); err != nil {
				log.Warn("sweep failed", "error", err)
			}
		}
	}
}
