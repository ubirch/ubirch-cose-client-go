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
	"github.com/lib/pq"
	"github.com/ubirch/ubirch-cose-client-go/main/config"

	log "github.com/sirupsen/logrus"
)

const (
	PostgreSql                  = "postgres"
	PostgreSqlIdentityTableName = "cose_identity_hsm"
	maxRetries                  = 2
)

const (
	PostgresIdentity = iota
)

var create = map[int]string{
	PostgresIdentity: fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, "+
		"public_key VARCHAR(255) NOT NULL, "+
		"auth VARCHAR(255) NOT NULL);", PostgreSqlIdentityTableName),
}

func (dm *DatabaseManager) CreateTable(tableType int) error {
	_, err := dm.db.Exec(create[tableType])
	return err
}

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options *sql.TxOptions
	db      *sql.DB
}

// Ensure Database implements the StorageManager interface
var _ StorageManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(dataSourceName string, dbParams *config.DatabaseParams) (*DatabaseManager, error) {
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
		db: pg,
	}

	if err = pg.Ping(); err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			// if there is no connection to the database yet, continue anyway.
			log.Warnf("connection to the database could not yet be established: %v", err)
		} else {
			return nil, err
		}
	} else {
		err = dm.CreateTable(PostgresIdentity)
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
	return nil
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx TransactionCtx, err error) {
	err = dm.retry(func() error {
		transactionCtx, err = dm.db.BeginTx(ctx, dm.options)
		return err
	})
	return transactionCtx, err
}

func (dm *DatabaseManager) StoreIdentity(transactionCtx TransactionCtx, i Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (uid, public_key, auth) VALUES ($1, $2, $3);",
		PostgreSqlIdentityTableName)

	_, err := tx.Exec(query, &i.Uid, &i.PublicKeyPEM, &i.Auth)

	return err
}

func (dm *DatabaseManager) LoadIdentity(uid uuid.UUID) (*Identity, error) {
	i := Identity{Uid: uid}

	query := fmt.Sprintf(
		"SELECT public_key, auth FROM %s WHERE uid = $1;",
		PostgreSqlIdentityTableName)

	err := dm.retry(func() error {
		err := dm.db.QueryRow(query, uid).Scan(&i.PublicKeyPEM, &i.Auth)
		if err == sql.ErrNoRows {
			return ErrNotExist
		}
		return err
	})

	return &i, err
}

func (dm *DatabaseManager) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	var uid uuid.UUID

	query := fmt.Sprintf(
		"SELECT uid FROM %s WHERE public_key = $1;",
		PostgreSqlIdentityTableName)

	err := dm.retry(func() error {
		err := dm.db.QueryRow(query, pubKey).Scan(&uid)
		if err == sql.ErrNoRows {
			return ErrNotExist
		}
		return err
	})

	return uid, err
}

func (dm *DatabaseManager) StoreAuth(transactionCtx TransactionCtx, uid uuid.UUID, auth string) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("UPDATE %s SET auth = $1 WHERE uid = $2;", PostgreSqlIdentityTableName)

	_, err := tx.Exec(query, &auth, uid)

	return err
}

func (dm *DatabaseManager) LoadAuthForUpdate(transactionCtx TransactionCtx, uid uuid.UUID) (auth string, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("SELECT auth FROM %s WHERE uid = $1 FOR UPDATE;", PostgreSqlIdentityTableName)

	err = tx.QueryRow(query, uid).Scan(&auth)
	if err == sql.ErrNoRows {
		return "", ErrNotExist
	}

	return auth, err
}

func (dm *DatabaseManager) retry(f func() error) (err error) {
	for retries := 0; retries <= maxRetries; retries++ {
		err = f()
		if err == nil || !dm.isRecoverable(err) {
			break
		}
		log.Warnf("database recoverable error: %v (%d / %d)", err, retries+1, maxRetries+1)
	}

	return err
}

func (dm *DatabaseManager) isRecoverable(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		switch pqErr.Code {
		case "42P01": // undefined_table
			err = dm.CreateTable(PostgresIdentity)
			if err != nil {
				log.Errorf("creating DB table failed: %v", err)
			}
			return true
		case "55P03", "53300", "53400": // lock_not_available, too_many_connections, configuration_limit_exceeded
			time.Sleep(10 * time.Millisecond)
			return true
		}
		log.Errorf("%s = %s", err, pqErr.Code)
	}
	return false
}
