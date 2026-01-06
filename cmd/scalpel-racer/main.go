// FILENAME: cmd/scalpel-racer/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/proxy"
	"github.com/xkilldash9x/scalpel-racer/internal/ui"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// -- Signal Handling --
	// sets up the root context that listens for OS interrupts
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := Run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func Run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("scalpel-racer", flag.ContinueOnError)
	port := flags.Int("p", config.DefaultProxyPort, "Proxy listen port")
	debug := flags.Bool("debug", false, "Enable debug logging")

	if err := flags.Parse(args); err != nil {
		return err
	}

	// -- Logging Setup --
	// configures zap for file output only to avoid messing with the TUI
	logConfig := zap.NewProductionConfig()
	logConfig.OutputPaths = []string{"racer.log"}
	logConfig.ErrorOutputPaths = []string{"racer.log"}
	logConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if *debug {
		logConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		logConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logger, err := logConfig.Build()
	if err != nil {
		return err
	}
	defer logger.Sync()

	// -- Proxy --
	proxyCfg := proxy.InterceptorConfig{
		Port:    *port,
		CertDir: "", // Use default
	}
	interceptor, err := proxy.NewInterceptor(proxyCfg, logger)
	if err != nil {
		return fmt.Errorf("proxy init error: %w", err)
	}
	if err := interceptor.Start(); err != nil {
		return fmt.Errorf("proxy start error: %w", err)
	}
	defer interceptor.Close()

	// -- Engine --
	racer := engine.NewRacer(&engine.RealClientFactory{}, logger)

	// -- UI --
	model := ui.NewModel(logger, racer)
	// passes the injected context to the tea program
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithContext(ctx),
		tea.WithInput(input),
		tea.WithOutput(output),
	)

	// -- Ingestion Bridge --
	// spins up a goroutine to bridge proxy requests to the UI program
	go func() {
		for {
			select {
			case req, ok := <-interceptor.CaptureChan():
				if !ok {
					return
				}
				p.Send(ui.CaptureMsg(req))
			case <-ctx.Done():
				return
			}
		}
	}()

	if _, err := p.Run(); err != nil {
		return err
	}

	return nil
}
