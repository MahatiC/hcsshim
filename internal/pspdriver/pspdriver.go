package pspdriver

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName = "AmdSnpPsp"
)

func StartPSPDriver(ctx context.Context) error {
	// Connect to the Service Control Manager
	m, err := mgr.Connect()
	if err != nil {
		return errors.Wrap(err, "Failed to connect to service manager")
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService(serviceName)
	if err != nil {
		return errors.Wrapf(err, "Could not access service %q", serviceName)
	}
	defer s.Close()

	// Start the service
	err = s.Start()
	if err != nil {
		return errors.Wrapf(err, "Could not start service %q", serviceName)
	}

	log.G(ctx).Tracef("Service %q started successfully\n", serviceName)

	// confirming the running state of the service
	status, err := s.Query()
	if err != nil {
		return errors.Wrap(err, "could not query service status")
	}

	switch status.State {
	case svc.Running:
		fmt.Println("Service is running.")
	case svc.Stopped:
		fmt.Println("Service is stopped.")
	case svc.StartPending:
		fmt.Println("Service is starting.")
	case svc.StopPending:
		fmt.Println("Service is stopping.")
	default:
		fmt.Printf("Service state: %v\n", status.State)
	}
	return nil
}
