// Copyright (c) 2021 ubirch GmbH
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
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	log "github.com/sirupsen/logrus"
)

const (
	PostgreSql                  string = "postgres"
	PostgreSqlIdentityTableName string = "cose_identity_hsm"
)

const (
	PostgresIdentity = iota
)

var create = map[int]string{
	PostgresIdentity: "CREATE TABLE IF NOT EXISTS %s(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"public_key VARCHAR(255) NOT NULL, " +
		"auth VARCHAR(255) NOT NULL);",
}

func CreateTable(tableType int, tableName string) string {
	return fmt.Sprintf(create[tableType], tableName)
}

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options   *sql.TxOptions
	db        *sql.DB
	tableName string
}

type DatabaseParams struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// Ensure Database implements the StorageManager interface
var _ StorageManager = (*DatabaseManager)(nil)

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

	log.Debugf("MaxOpenConns: %d", dbParams.MaxOpenConns)
	log.Debugf("MaxIdleConns: %d", dbParams.MaxIdleConns)
	log.Debugf("ConnMaxLifetime: %s", dbParams.ConnMaxLifetime.String())
	log.Debugf("ConnMaxIdleTime: %s", dbParams.ConnMaxIdleTime.String())

	dm := &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		},
		db:        pg,
		tableName: tableName,
	}

	if err = pg.Ping(); err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			// if there is no connection to the database yet, continue anyway.
			log.Warnf("connection to the database could not yet be established: %v", err)
		} else {
			return nil, err
		}
	} else {
		_, err = dm.db.Exec(CreateTable(PostgresIdentity, tableName))
		if err != nil {
			return nil, fmt.Errorf("creating DB table failed: %v", err)
		}
	}

	return dm, nil
}

func (dm *DatabaseManager) Close() {
	err := dm.db.Close()
	if err != nil {
		log.Errorf("failed to close database: %v", err)
	}
}

func (dm *DatabaseManager) IsReady() error {
	if err := dm.db.Ping(); err != nil {
		return fmt.Errorf("database not ready: %v", err)
	}

	// create table if it does not exist yet
	_, err := dm.db.Exec(CreateTable(PostgresIdentity, dm.tableName))
	if err != nil {
		return fmt.Errorf("database connection was established but creating table failed: %v", err)
	}
	return nil
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx TransactionCtx, err error) {
	return dm.db.BeginTx(ctx, dm.options)
}

func (dm *DatabaseManager) StoreIdentity(transactionCtx TransactionCtx, i Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (uid, public_key, auth) VALUES ($1, $2, $3);",
		dm.tableName)

	_, err := tx.Exec(query, &i.Uid, &i.PublicKeyPEM, &i.Auth)

	return err
}

func (dm *DatabaseManager) LoadIdentity(uid uuid.UUID) (*Identity, error) {
	i := Identity{Uid: uid}

	query := fmt.Sprintf(
		"SELECT public_key, auth FROM %s WHERE uid = $1;",
		dm.tableName)

	err := dm.db.QueryRow(query, uid).Scan(&i.PublicKeyPEM, &i.Auth)
	if err == sql.ErrNoRows {
		return nil, ErrNotExist
	}

	return &i, err
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

func (dm *DatabaseManager) StoreAuth(transactionCtx TransactionCtx, uid uuid.UUID, auth string) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("UPDATE %s SET auth = $1 WHERE uid = $2;", dm.tableName)

	_, err := tx.Exec(query, &auth, uid)

	return err
}

func (dm *DatabaseManager) LoadAuthForUpdate(transactionCtx TransactionCtx, uid uuid.UUID) (auth string, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("SELECT auth FROM %s WHERE uid = $1 FOR UPDATE;", dm.tableName)

	err = tx.QueryRow(query, uid).Scan(&auth)
	if err == sql.ErrNoRows {
		return "", ErrNotExist
	}

	return auth, err
}
