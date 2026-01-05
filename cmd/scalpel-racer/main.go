// FILENAME: cmd/scalpel-racer/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/proxy"
	"github.com/xkilldash9x/scalpel-racer/internal/ui"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// UIRunner defines an interface to abstract the blocking UI call.
type UIRunner interface {
	Run(p *tea.Program) (tea.Model, error)
}

type DefaultRunner struct{}

func (r *DefaultRunner) Run(p *tea.Program) (tea.Model, error) {
	return p.Run()
}

func main() {
	if err := Run(os.Args[1:], nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Run executes the application logic.
func Run(args []string, runner UIRunner) error {
	// 1. Argument Parsing
	flags := flag.NewFlagSet("scalpel-racer", flag.ContinueOnError)
	port := flags.Int("p", 8080, "Proxy listen port")
	debug := flags.Bool("debug", false, "Enable debug logging")

	if err := flags.Parse(args); err != nil {
		return err
	}

	// 2. Setup Logger (File-Based for TUI Compatibility)
	// CRITICAL FIX: We cannot log to stdout/stderr while the TUI is active.
	// Doing so corrupts the rendering buffer (see artifacts in image_2d42a1.png).
	// We redirect all telemetry to 'racer.log'.
	logConfig := zap.NewProductionConfig()
	logConfig.OutputPaths = []string{"racer.log"}
	logConfig.ErrorOutputPaths = []string{"racer.log"}

	// Adjust encoder to be human-readable in the file
	logConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	if *debug {
		logConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		logConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, err := logConfig.Build()
	if err != nil {
		return fmt.Errorf("failed to initialize file logger: %w", err)
	}
	defer logger.Sync()

	// Note: We are bypassing observability.InitializeLogger because it enforces
	// console output which is incompatible with the Bubble Tea runtime.

	// 3. Signal Handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 4. Start Proxy
	interceptor, err := proxy.NewInterceptor(*port, logger)
	if err != nil {
		return fmt.Errorf("proxy init error: %w", err)
	}
	if err := interceptor.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}
	defer interceptor.Close()

	// 5. Initialize Core Engine
	racer := engine.NewRacer(&engine.RealClientFactory{}, logger)

	// 6. Start UI
	model := ui.NewModel(logger, racer)

	// Redirect BubbleTea's internal logs to a file as well, just in case
	if f, err := tea.LogToFile("debug.log", "debug"); err == nil {
		defer f.Close()
	}

	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx))

	// 7. Ingestion Pipeline (Non-Blocking)
	// We handle heavy disk writes here, in a background goroutine,
	// so the UI thread receives lightweight messages.
	go func() {
		defer cancel()
		const MaxRamBody = 10 * 1024 // 10KB Limit for RAM

		for {
			select {
			case req, ok := <-interceptor.CaptureChan:
				if !ok {
					return
				}

				// PERF: Offload large bodies to disk immediately.
				if len(req.Body) > MaxRamBody {
					f, err := os.CreateTemp("", "scalpel-body-*")
					if err == nil {
						if _, wErr := f.Write(req.Body); wErr == nil {
							req.OffloadPath = f.Name()
							req.Body = nil // Free RAM
						}
						f.Close()
					} else {
						logger.Error("failed to offload body", zap.Error(err))
					}
				}

				p.Send(ui.CaptureMsg(req))

			case <-ctx.Done():
				return
			}
		}
	}()

	// 8. Run Program
	if runner == nil {
		runner = &DefaultRunner{}
	}
	if _, err := runner.Run(p); err != nil {
		return fmt.Errorf("ui run error: %w", err)
	}

	return nil
}
