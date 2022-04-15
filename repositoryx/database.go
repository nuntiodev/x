package database

import (
	"context"

	"github.com/nuntiodev/x/repositoryx/mongo_client"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type Database struct {
	zapLog *zap.Logger
}

func CreateDatabase(zapLog *zap.Logger) (*Database, error) {
	return &Database{
		zapLog: zapLog,
	}, nil
}

func (db *Database) CreateMongoClient(ctx context.Context) (*mongo.Client, error) {
	return mongo_client.CreateMongoClient(ctx, db.zapLog)
}
