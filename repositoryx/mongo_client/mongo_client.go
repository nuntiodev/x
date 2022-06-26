package mongo_client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nuntiodev/x/retryx"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

var (
	mongoUri          = ""
	mongoUser         = ""
	mongoUserPassword = ""
	mongoHost         = ""
)

func initializeMongoClient() error {
	var ok bool
	mongoUri, ok = os.LookupEnv("MONGO_URI")
	if ok && mongoUri != "" {
		return nil
	}
	mongoUser, ok = os.LookupEnv("MONGO_DB_USER")
	if !ok {
		return errors.New("missing required MONGO_DB_USER")
	}
	mongoUserPassword, ok = os.LookupEnv("MONGO_DB_USER_PASSWORD")
	if !ok {
		return errors.New("missing required MONGO_DB_USER_PASSWORD")
	}
	mongoHost, ok = os.LookupEnv("MONGO_DB_HOST")
	if !ok || mongoHost == "" {
		return errors.New("missing required MONGO_DB_HOST")
	}
	return nil
}

func CreateMongoClient(ctx context.Context, zapLog *zap.Logger, retry *int) (*mongo.Client, error) {
	zapLog.Info("trying to create mongo client...")
	if err := initializeMongoClient(); err != nil {
		return nil, err
	}
	withRetry := 1
	if retry != nil && *retry > 0 {
		withRetry = *retry
	}
	// either specify uri or user, host and password
	if mongoUri == "" {
		mongoUri = fmt.Sprintf("mongodb+srv://%s:%s@%s/?retryWrites=true&w=majority", mongoUser, mongoUserPassword, mongoHost)
	}
	var client *mongo.Client
	if err := retryx.Retry(withRetry, time.Second*5, func() (err error) {
		client, err = mongo.Connect(ctx, options.Client().ApplyURI(
			mongoUri,
		))
		if err != nil {
			zapLog.Error(fmt.Sprintf("could not connect to MongoDB with err: %v", err))
			return err
		}
		return nil
	}); err != nil {
		zapLog.Error(fmt.Sprintf("could not connect to mongo with uri %s", mongoUri))
		return nil, err
	}
	if err := PerformMongHealthCheck(ctx, client); err != nil {
		return nil, err
	}
	zapLog.Info("mongo client created...")
	return client, nil
}

func PerformMongHealthCheck(ctx context.Context, client *mongo.Client) error {
	if err := checkMongoConnection(ctx, client); err != nil {
		return err
	}
	return nil
}

func checkMongoConnection(ctx context.Context, client *mongo.Client) error {
	if err := client.Ping(ctx, nil); err != nil {
		return err
	}
	return nil
}
