package email_mock

// todo: move to softcorp-io/x

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.uber.org/zap"
)

func getFreePort() string {
	// get random free port
	for {
		ln, err := net.Listen("tcp", ":"+"0")
		if err == nil {
			port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
			ln.Close()
			return port
		}
		ln.Close()
	}
}

func removeContainer(pool *dockertest.Pool, container *dockertest.Resource, containerName string) error {
	if pool != nil {
		if err := pool.Purge(container); err != nil {
			fmt.Printf("failed to purge pool with err: %s\n", err)
			return err
		}
		if err := pool.RemoveContainerByName(containerName); err != nil {
			fmt.Printf("failed to remove Docker container with err: %s\n", err)
			return err
		}
	}
	return nil
}

/*
	NewDatabaseMock spins up a mongodb database
*/
func NewEmailMock(ctx context.Context, zapLog *zap.Logger, containerName string) (string, func() error, error) {
	// create the pool (docker instance).
	pool, err := dockertest.NewPool("")
	if err != nil {
		return "", nil, err
	}
	// remove old containers
	if err := pool.RemoveContainerByName(containerName); err != nil {
		return "", nil, err
	}
	// start the container.
	wwwPort := getFreePort()
	servicePort := getFreePort()
	smtpPort := getFreePort()
	container, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "oryd/mailslurper",
		Name:         containerName,
		Tag:          "smtps-latest",
		ExposedPorts: []string{"8080", "8085", "2500"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8080": {
				{HostIP: "0.0.0.0", HostPort: wwwPort},
			},
			"8085": {
				{HostIP: "0.0.0.0", HostPort: servicePort},
			},
			"2500": {
				{HostIP: "0.0.0.0", HostPort: smtpPort},
			},
		},
	})
	if err != nil {
		return "", nil, err
	}
	// setup mail connection
	return smtpPort, func() error {
		return removeContainer(pool, container, containerName)
	}, nil
}
