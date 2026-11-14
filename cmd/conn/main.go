// Command conn runs the ClearedStack Command Portal, contractor tool catalog,
// Muster SSE live-feed relay, and anonymous Proof-of-Work intake server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ClearedStack/conn/internal/feedhub"
	"github.com/ClearedStack/conn/internal/muster"
	"github.com/ClearedStack/conn/internal/ownership"
	"github.com/ClearedStack/conn/internal/pgwire"
	"github.com/ClearedStack/conn/internal/pubstore"
	"github.com/ClearedStack/conn/internal/web"
)

// Version matches component.json.
const Version = "v0.2.0-draft"

const (
	defaultListenAddr       = ":8080"
	defaultTokenFile        = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultOwnershipMapPath = "/etc/conn/ownership/ownership_map.json"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "conn: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return serveCmd(ctx, nil, stdout, stderr)
	}
	switch args[0] {
	case "serve":
		return serveCmd(ctx, args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "conn %s\n", Version)
		return nil
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		if strings.HasPrefix(args[0], "-") {
			return serveCmd(ctx, args, stdout, stderr)
		}
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  conn serve [flags]")
	fmt.Fprintln(w, "  conn version")
}

type serveOptions struct {
	listenAddr       string
	standalone       bool
	databaseURL      string
	databasePassFile string
	musterURL        string
	tokenFile        string
	ownershipMapPath string
}

func parseServeFlags(args []string, stderr io.Writer) (serveOptions, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	defListen := envOrDefault("CONN_LISTEN", defaultListenAddr)
	defStandalone := envBool("CONN_STANDALONE")
	defDBURL := os.Getenv("CONN_DATABASE_URL")
	defDBPassFile := os.Getenv("CONN_DATABASE_PASSWORD_FILE")
	defMusterURL := envOrDefault("MUSTER_URL", os.Getenv("CONN_MUSTER_URL"))
	defTokenFile := envOrDefault("CONN_TOKEN_FILE", defaultTokenFile)
	defOwnership := os.Getenv("CONN_OWNERSHIP_MAP")

	var opts serveOptions
	fs.StringVar(&opts.listenAddr, "listen", defListen, "TCP listen address")
	fs.BoolVar(&opts.standalone, "standalone", defStandalone, "Run with in-memory synthetic store and Muster stand-in")
	fs.StringVar(&opts.databaseURL, "database-url", defDBURL, "PostgreSQL read-only URL (pub_ro)")
	fs.StringVar(&opts.databasePassFile, "database-password-file", defDBPassFile, "Path to mounted database password file")
	fs.StringVar(&opts.musterURL, "muster-url", defMusterURL, "Muster base URL (e.g. http://muster.clearedstack.svc.cluster.local)")
	fs.StringVar(&opts.tokenFile, "token-file", defTokenFile, "Kubernetes ServiceAccount token path")
	fs.StringVar(&opts.ownershipMapPath, "ownership-map", defOwnership, "Path to ownership_map.json")

	if err := fs.Parse(args); err != nil {
		return serveOptions{}, err
	}
	if fs.NArg() > 0 {
		return serveOptions{}, fmt.Errorf("unexpected positional argument %q", fs.Arg(0))
	}
	return opts, nil
}

func serveCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	opts, err := parseServeFlags(args, stderr)
	if err != nil {
		return err
	}

	logger := log.New(stderr, "conn: ", log.LUTC|log.LstdFlags)

	var (
		store      pubstore.Reader
		musterCli  *muster.Client
		owners     *ownership.Map
		closeFuncs []func()
	)
	defer func() {
		for i := len(closeFuncs) - 1; i >= 0; i-- {
			closeFuncs[i]()
		}
	}()

	if opts.standalone {
		if opts.ownershipMapPath != "" {
			owners, err = ownership.LoadFile(opts.ownershipMapPath)
			if err != nil {
				return err
			}
		} else {
			owners, err = ownership.Parse([]byte(muster.DefaultStandinOwnershipJSON))
			if err != nil {
				return err
			}
		}

		store = pubstore.NewMemoryStore()

		standin := muster.NewStandin([]muster.SeedItem{
			{ID: "PA-0014", State: "discovered", Lane: "normal"},
			{ID: "PA-0013", State: "recorded", Lane: "normal"},
			{ID: "PA-0012", State: "observed", Lane: "normal"},
			{ID: "PA-0010", State: "scored", Lane: "normal"},
			{ID: "PA-0009", State: "approved", Lane: "urgent"},
		}, owners)
		standin.SetClock(time.Now().UTC())

		ln, lerr := net.Listen("tcp", "127.0.0.1:0")
		if lerr != nil {
			return errors.New("unable to bind loopback listener for standalone muster stand-in")
		}
		standinHTTP := &http.Server{
			Handler:           standin,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			_ = standinHTTP.Serve(ln)
		}()
		closeFuncs = append(closeFuncs, func() {
			_ = standinHTTP.Close()
		})

		// Keep Standin clock synced to UTC wall time and emit periodic 5s depths ticks.
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-ticker.C:
					standin.SetClock(now.UTC())
					standin.BroadcastTick()
				}
			}
		}()

		localURL := "http://" + ln.Addr().String()
		musterCli, err = muster.NewClient(localURL, muster.StaticTokenSource(standin.TokenFor("conn")), nil)
		if err != nil {
			return err
		}
	} else {
		if strings.TrimSpace(opts.databaseURL) == "" {
			return errors.New("missing -database-url or CONN_DATABASE_URL (or pass -standalone)")
		}
		if strings.TrimSpace(opts.musterURL) == "" {
			return errors.New("missing -muster-url or MUSTER_URL (or pass -standalone)")
		}

		mapPath := opts.ownershipMapPath
		if mapPath == "" {
			mapPath = defaultOwnershipMapPath
		}
		owners, err = ownership.LoadFile(mapPath)
		if err != nil {
			return err
		}

		passwordOverride := ""
		if strings.TrimSpace(opts.databasePassFile) != "" {
			rawPass, perr := os.ReadFile(opts.databasePassFile)
			if perr != nil {
				return errors.New("unable to read database password file")
			}
			passwordOverride = strings.TrimRight(string(rawPass), "\r\n")
		}

		pgCfg, perr := pgwire.ParseConfig(opts.databaseURL, passwordOverride)
		if perr != nil {
			return perr
		}
		pool, perr := pgwire.NewPool(pgCfg)
		if perr != nil {
			return perr
		}
		closeFuncs = append(closeFuncs, func() {
			_ = pool.Close()
		})
		store = pubstore.NewPGStore(pool)

		musterCli, err = muster.NewClient(opts.musterURL, muster.FileTokenSource(opts.tokenFile), nil)
		if err != nil {
			return err
		}
	}

	hub := feedhub.New(musterCli, feedhub.Config{})
	go hub.Run(ctx)

	webSrv, err := web.NewServer(web.Config{
		Store:  store,
		Muster: musterCli,
		Hub:    hub,
		Owners: owners,
	})
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", opts.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s failed", opts.listenAddr)
	}

	httpSrv := &http.Server{
		Handler:           webSrv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      0, // Disabled so long-lived GET /v1/feed SSE streams remain open.
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("serving on %s (standalone=%v version=%s)", ln.Addr().String(), opts.standalone, Version)
		if serr := httpSrv.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			errCh <- serr
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return <-errCh
	case serr := <-errCh:
		return serr
	}
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
