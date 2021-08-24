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

package repository

import (
	"database/sql"
	"fmt"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-cose-client-go/main/ent"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	log "github.com/sirupsen/logrus"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const (
	PostgreSql                  string = "postgres"
	PostgreSqlIdentityTableName string = "cose_identity_hsm"
)

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	postgresDSN string
	options     *sql.TxOptions
	db          *sql.DB
	tableName   string
}

// Ensure Database implements the ContextManager interface
var _ StorageManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(postgresDSN, tableName string, dbParams *config.DatabaseParams) (*DatabaseManager, error) {
	log.Infof("preparing postgres usage")
	pg, err := sql.Open(PostgreSql, postgresDSN)
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
		postgresDSN: postgresDSN,
		options: &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		},
		db:        pg,
		tableName: tableName,
	}

	if err = pg.Ping(); err != nil {
		// if there is no connection to the database yet, continue anyway.
		log.Warnf("connection to the database could not yet be established: %v", err)
	} else {
		err = RunMigrations("file://./migration", postgresDSN, "public")
		if err != nil {
			return nil, err
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

func (dm *DatabaseManager) StoreNewIdentity(id ent.Identity) error {
	query := fmt.Sprintf(
		"INSERT INTO %s (uid, public_key, auth) VALUES ($1, $2, $3);",
		dm.tableName)

	_, err := dm.db.Exec(query,
		&id.Uid,
		&id.PublicKeyPEM,
		&id.Auth)
	if err != nil {
		return err
	}

	return nil
}

func (dm *DatabaseManager) GetIdentity(uid uuid.UUID) (ent.Identity, error) {
	var id ent.Identity

	query := fmt.Sprintf("SELECT * FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid).Scan(
		&id.Uid,
		&id.PublicKeyPEM,
		&id.Auth)
	if err != nil {
		if err == sql.ErrNoRows {
			return id, ErrNotExist
		}
		return id, err
	}

	return id, nil
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

func (dm *DatabaseManager) IsRecoverable(err error) bool {
	if err.Error() == pq.ErrorCode("53300").Name() || // "53300": "too_many_connections",
		err.Error() == pq.ErrorCode("53400").Name() { // "53400": "configuration_limit_exceeded",
		time.Sleep(10 * time.Millisecond)
		return true
	}

	tableDoesNotExistError := fmt.Sprintf("relation \"%s\" does not exist", dm.tableName)
	if strings.Contains(err.Error(), tableDoesNotExistError) {
		err = RunMigrations("file://./migration", dm.postgresDSN, "public")
		if err != nil {
			log.Errorf("an error occured when trying to create DB table \"%s\": %v", dm.tableName, err)
			return false
		}
		return true
	}

	return false
}
