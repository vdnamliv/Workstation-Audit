//go:build windows
// +build windows

package svcwin

import (
	"context"
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

type Runner interface {
	// one-run: fetch policies -> audit -> post results
	RunOnce(ctx context.Context) error
	// poll interval (seconds)
	PollInterval() int
}

// Service implements windows/svc.Handler
type Service struct {
	runner Runner
}

func NewService(r Runner) *Service { return &Service{runner: r} }

func (m *Service) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: accepts}

	// main loop
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		poll := m.runner.PollInterval()
		if poll <= 0 { poll = 600 }
		t := time.NewTicker(time.Duration(poll) * time.Second)
		defer t.Stop()

		ctx := context.Background()
		for {
			// run once
			if err := m.runner.RunOnce(ctx); err != nil {
				log.Printf("service runOnce error: %v", err)
			}
			select {
			case <-t.C:
				continue
			case <-stop:
				return
			}
		}
	}()

	// control loop
loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		default:
			// ignore
		}
	}
	// ask worker to stop and wait a moment
	close(stop)
	status <- svc.Status{State: svc.StopPending}
	time.Sleep(800 * time.Millisecond)
	status <- svc.Status{State: svc.Stopped}
	return
}

// Run attaches to SCM if running as a real service; otherwise returns error.
func Run(name string, s *Service) error {
	return svc.Run(name, s)
}

// IsWindowsService tells if process is started by SCM
func IsWindowsService() bool {
	inSvc, err := svc.IsWindowsService()
	return err == nil && inSvc
}
