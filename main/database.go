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
	PostgreSqlPort              int    = 5432
	PostgreSqlIdentityTableName string = "cose_identity"
)

const (
	PostgresIdentity = iota
)

var CREATE = map[int]string{
	PostgresIdentity: "CREATE TABLE IF NOT EXISTS " + PostgreSqlIdentityTableName + "(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",
}

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options *sql.TxOptions
	db      *sql.DB
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(conf *Config) (*DatabaseManager, error) {
	dataSourceName := fmt.Sprintf("host=%s user=%s password=%s port=%d dbname=%s sslmode=disable",
		conf.DsnHost, conf.DsnUser, conf.DsnPassword, PostgreSqlPort, conf.DsnDb)

	pg, err := sql.Open(PostgreSql, dataSourceName)
	if err != nil {
		return nil, err
	}
	pg.SetMaxOpenConns(100)
	pg.SetMaxIdleConns(70)
	pg.SetConnMaxLifetime(10 * time.Minute)
	if err = pg.Ping(); err != nil {
		return nil, err
	}

	log.Print("preparing postgres usage")

	dbManager := &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		},
		db: pg,
	}

	if _, err = dbManager.db.Exec(CREATE[PostgresIdentity]); err != nil {
		return nil, err
	}

	return dbManager, nil
}

func (dm *DatabaseManager) ExistsPrivateKey(uid uuid.UUID) (bool, error) {
	var privateKey []byte

	err := dm.db.QueryRow("SELECT private_key FROM cose_identity WHERE uid = $1", uid.String()).
		Scan(&privateKey)
	if err != nil {
		if dm.isConnectionAvailable(err) {
			return dm.ExistsPrivateKey(uid)
		}
		if err == sql.ErrNoRows || len(privateKey) == 0 {
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}

func (dm *DatabaseManager) ExistsPublicKey(uid uuid.UUID) (bool, error) {
	var publicKey []byte

	err := dm.db.QueryRow("SELECT public_key FROM cose_identity WHERE uid = $1", uid.String()).
		Scan(&publicKey)
	if err != nil {
		if dm.isConnectionAvailable(err) {
			return dm.ExistsPublicKey(uid)
		}
		if err == sql.ErrNoRows || len(publicKey) == 0 {
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}

func (dm *DatabaseManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	var privateKey []byte

	err := dm.db.QueryRow("SELECT private_key FROM cose_identity WHERE uid = $1", uid.String()).
		Scan(&privateKey)
	if err != nil {
		if dm.isConnectionAvailable(err) {
			return dm.GetPrivateKey(uid)
		}
		return nil, err
	}

	return privateKey, nil
}

func (dm *DatabaseManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	var publicKey []byte

	err := dm.db.QueryRow("SELECT public_key FROM cose_identity WHERE uid = $1", uid.String()).
		Scan(&publicKey)
	if err != nil {
		if dm.isConnectionAvailable(err) {
			return dm.GetPublicKey(uid)
		}
		return nil, err
	}

	return publicKey, nil
}

func (dm *DatabaseManager) GetAuthToken(uid uuid.UUID) (string, error) {
	var authToken string

	err := dm.db.QueryRow("SELECT auth_token FROM cose_identity WHERE uid = $1", uid.String()).
		Scan(&authToken)
	if err != nil {
		if dm.isConnectionAvailable(err) {
			return dm.GetAuthToken(uid)
		}
		return "", err
	}

	return authToken, nil
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return dm.db.BeginTx(ctx, dm.options)
}

// StartTransactionWithLock starts a transaction and acquires a lock on the row with the specified uuid as key.
// Returns error if row does not exist.
func (dm *DatabaseManager) StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error) {
	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return nil, err
	}

	var id string

	// lock row FOR UPDATE
	err = tx.QueryRow("SELECT uid FROM cose_identity WHERE uid = $1 FOR UPDATE", uid).
		Scan(&id)
	if err != nil {
		if dm.isConnectionAvailable(err) {
			return dm.StartTransactionWithLock(ctx, uid)
		}
		return nil, err
	}

	return tx, nil
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

	// make sure identity does not exist yet
	var uid string

	err := tx.QueryRow("SELECT uid FROM cose_identity WHERE uid = $1 FOR UPDATE", identity.Uid.String()).
		Scan(&uid)
	if err != nil {
		if dm.isConnectionAvailable(err) {
			return dm.StoreNewIdentity(tx, identity)
		}
		if err == sql.ErrNoRows {
			// there were no rows, but otherwise no error occurred
			return dm.storeIdentity(tx, identity)
		} else {
			return err
		}
	} else {
		return ErrExists
	}
}

func (dm *DatabaseManager) storeIdentity(tx *sql.Tx, identity Identity) error {
	_, err := tx.Exec(
		"INSERT INTO cose_identity (uid, private_key, public_key, auth_token) VALUES ($1, $2, $3, $4);",
		&identity.Uid, &identity.PrivateKey, &identity.PublicKey, &identity.AuthToken)
	if err != nil {
		if dm.isConnectionAvailable(err) {
			return dm.storeIdentity(tx, identity)
		}
		return err
	}

	return nil
}

func (dm *DatabaseManager) isConnectionAvailable(err error) bool { // todo this will only work with postgres
	if err.Error() == pq.ErrorCode("53300").Name() || // "53300": "too_many_connections",
		err.Error() == pq.ErrorCode("53400").Name() { // "53400": "configuration_limit_exceeded",
		time.Sleep(100 * time.Millisecond)
		return true
	}
	return false
}
