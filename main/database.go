// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"time"
	// postgres driver is imported for side effects
	// import pq driver this way only if we dont need it here
	// done for database/sql (pg, err := sql.Open..)
	//_ "github.com/lib/pq"
)

const (
	PostgreSql                  string = "postgres"
	PostgreSqlIdentityTableName string = "cose_identity"
)

const (
	PostgresIdentity = iota
)

var create = map[int]string{
	PostgresIdentity: "CREATE TABLE IF NOT EXISTS %s(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",
}

func CreateTable(tableType int, tableName string) string {
	return fmt.Sprintf(create[tableType], tableName)
}

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options           *sql.TxOptions
	db                *sql.DB
	tableName         string
	listener          *pq.Listener
	updateChannelName string
}

type DatabaseParams struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(dataSourceName, tableName string, dbParams *DatabaseParams) (*DatabaseManager, error) {
	log.Infof("preparing postgres usage")

	pg, err := sql.Open(PostgreSql, dataSourceName)
	if err != nil {
		return nil, err
	}
	pg.SetMaxOpenConns(dbParams.MaxOpenConns)
	pg.SetMaxIdleConns(dbParams.MaxIdleConns)
	pg.SetConnMaxLifetime(dbParams.ConnMaxLifetime)
	pg.SetConnMaxIdleTime(dbParams.ConnMaxIdleTime)
	if err = pg.Ping(); err != nil {
		return nil, err
	}

	log.Debugf("MaxOpenConns: %d", dbParams.MaxOpenConns)
	log.Debugf("MaxIdleConns: %d", dbParams.MaxIdleConns)
	log.Debugf("ConnMaxLifetime: %s", dbParams.ConnMaxLifetime.String())
	log.Debugf("ConnMaxIdleTime: %s", dbParams.ConnMaxIdleTime.String())

	dm := &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: sql.LevelSerializable,
			ReadOnly:  false,
		},
		db:        pg,
		tableName: tableName,
	}

	_, err = dm.db.Exec(CreateTable(PostgresIdentity, tableName))
	if err != nil {
		return nil, err
	}

	dm.updateChannelName = "update"

	dm.listener, err = initListener(dataSourceName, dm.updateChannelName)
	if err != nil {
		return nil, err
	}

	return dm, nil
}

func (dm *DatabaseManager) Close() {
	err := dm.listener.Close()
	if err != nil {
		log.Errorf("failed to close db listener connection: %v", err)
	}
	err = dm.db.Close()
	if err != nil {
		log.Errorf("failed to close database: %v", err)
	}
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return dm.db.BeginTx(ctx, dm.options)
}

func (dm *DatabaseManager) CloseTransaction(transactionCtx interface{}, commit bool) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	if commit {
		return tx.Commit()
	} else {
		return tx.Rollback()
	}
}

func (dm *DatabaseManager) StoreNewIdentity(transactionCtx interface{}, identity Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (uid, private_key, public_key, auth_token) VALUES ($1, $2, $3, $4);",
		dm.tableName)

	_, err := tx.Exec(query, &identity.Uid, &identity.PrivateKey, &identity.PublicKey, &identity.AuthToken)
	if err != nil {
		return err
	}

	return nil
}

func (dm *DatabaseManager) GetIdentity(uid uuid.UUID) (*Identity, error) {
	var id Identity

	query := fmt.Sprintf("SELECT * FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&id.Uid, &id.PrivateKey, &id.PublicKey, &id.AuthToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotExist
		}
		return nil, err
	}

	return &id, nil
}

func (dm *DatabaseManager) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	var uid uuid.UUID

	query := fmt.Sprintf("SELECT uid FROM %s WHERE public_key = $1", dm.tableName)

	err := dm.db.QueryRow(query, pubKey).Scan(&uid)
	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, ErrNotExist
		}
		return uuid.Nil, err
	}

	return uid, nil
}

func isConnectionNotAvailable(err error) bool {
	if err.Error() == pq.ErrorCode("53300").Name() || // "53300": "too_many_connections",
		err.Error() == pq.ErrorCode("53400").Name() { // "53400": "configuration_limit_exceeded",
		time.Sleep(10 * time.Millisecond)
		return true
	}
	return false
}
