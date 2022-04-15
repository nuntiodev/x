package mongo_mock

// todo: move to softcorp-io/x

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	database "github.com/nuntiodev/x/repositoryx"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

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
func NewDatabaseMock(ctx context.Context, zapLog *zap.Logger, containerName string) (*mongo.Client, func() error, error) {
	// create the pool (docker instance).
	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, nil, err
	}
	// remove old containers
	if err := pool.RemoveContainerByName(containerName); err != nil {
		return nil, nil, err
	}
	// get random free port
	mongoPort := ""
	for {
		ln, err := net.Listen("tcp", ":"+"0")
		if err == nil {
			mongoPort = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
			ln.Close()
			break
		}
		ln.Close()
	}
	// start the container.
	container, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "mongo",
		Name:         containerName,
		Tag:          "latest",
		ExposedPorts: []string{"27017"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"27017": {
				{HostIP: "0.0.0.0", HostPort: mongoPort},
			},
		},
	})
	if err != nil {
		return nil, nil, err
	}
	// setup environment
	mongoUri := "mongodb://localhost:" + mongoPort
	os.Setenv("MONGO_URI", mongoUri)
	// check db connection and create mongo client
	var mongoClient *mongo.Client
	if err = pool.Retry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		db, err := database.CreateDatabase(zapLog)
		client, err := db.CreateMongoClient(ctx)
		if err != nil {
			return err
		}
		mongoClient = client
		return nil
	}); err != nil {
		if err := pool.Purge(container); err != nil {
			zapLog.Fatal(fmt.Sprintf("failed to purge pool with err: %s", err))
		}
		if err := pool.RemoveContainerByName(containerName); err != nil {
			zapLog.Fatal(fmt.Sprintf("failed to remove Docker container with err: %s", err))
		}
		return nil, func() error {
			return removeContainer(pool, container, containerName)
		}, err
	}
	return mongoClient, func() error {
		return removeContainer(pool, container, containerName)
	}, nil
}
