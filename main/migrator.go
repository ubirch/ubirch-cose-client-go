package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	MigrationID      = "cose_identity_db_migration"
	MigrationVersion = "2.0"
	VersionTableName = "version"
)

type Migration struct {
	Id               string
	MigrationVersion string
}

func Migrate(c *Config) error {
	dm, err := NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName)
	if err != nil {
		return err
	}

	v, err := getVersion(dm)
	if err != nil {
		return err
	}
	if v.MigrationVersion == MigrationVersion {
		log.Infof("database migration version already up to date")
		return nil
	}
	log.Debugf("database migration version: %s / application migration version: %s", v.MigrationVersion, MigrationVersion)

	if strings.HasPrefix(v.MigrationVersion, "0.") {
		err = migrateFileToDB(c, dm)
		if err != nil {
			return err
		}

		p, err := NewProtocol(dm, c.secretBytes, c.saltBytes, nil, false)
		if err != nil {
			return err
		}

		err = encryptTokens(dm, p)
		if err != nil {
			return err
		}

		log.Infof("successfully encrypted auth tokens in database")
	}

	return updateVersion(dm, v)
}

func migrateFileToDB(c *Config, dm *DatabaseManager) error {
	identities := new([]*Identity)

	err := c.loadIdentitiesFile(identities)
	if err != nil {
		return err
	}

	err = c.loadTokens(identities)
	if err != nil {
		return err
	}

	err = getKeysFromFile(c.configDir, identities)
	if err != nil {
		return err
	}

	err = migrateIdentities(dm, identities)
	if err != nil {
		return err
	}

	log.Infof("successfully migrated file based context into database")
	return nil
}

func getKeysFromFile(configDir string, identities *[]*Identity) (err error) {
	fileManager, err := NewFileManager(configDir)
	if err != nil {
		return err
	}

	for _, i := range *identities {
		i.PrivateKey, err = fileManager.GetPrivateKey(i.Uid)
		if err != nil {
			return fmt.Errorf("%s: %v", i.Uid, err)
		}

		i.PublicKey, err = fileManager.GetPublicKey(i.Uid)
		if err != nil {
			return fmt.Errorf("%s: %v", i.Uid, err)
		}
	}

	return nil
}

func migrateIdentities(dm *DatabaseManager, identities *[]*Identity) error {
	log.Infof("starting migration...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	if err != nil {
		return err
	}

	for i, id := range *identities {
		log.Infof("%4d: %s", i+1, id.Uid)

		if len(id.PrivateKey) == 0 {
			return fmt.Errorf("%s: empty private key", id.Uid)
		}

		if len(id.PublicKey) == 0 {
			return fmt.Errorf("%s: empty public key", id.Uid)
		}

		if len(id.AuthToken) == 0 {
			return fmt.Errorf("%s: empty auth token", id.Uid)
		}

		err = dm.StoreNewIdentity(tx, *id)
		if err != nil {
			if err == ErrExists {
				log.Warnf("%s: %v -> skip", id.Uid, err)
			} else {
				return err
			}
		}
	}

	return dm.CloseTransaction(tx, Commit)
}

func encryptTokens(dm *DatabaseManager, p *Protocol) error {
	query := fmt.Sprintf("SELECT uid, auth_token FROM %s", dm.tableName)

	rows, err := dm.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var (
		uid  uuid.UUID
		auth string
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		return err
	}

	for rows.Next() {
		err = rows.Scan(&uid, &auth)
		if err != nil {
			return err
		}

		err = p.SetAuthToken(tx, uid, auth)
		if err != nil {
			return err
		}
	}
	if rows.Err() != nil {
		return rows.Err()
	}

	return p.CloseTransaction(tx, Commit)
}

func createVersionTable(dm *DatabaseManager) error {
	query := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"id VARCHAR(255) NOT NULL PRIMARY KEY, "+
		"migration_version VARCHAR(255) NOT NULL);", VersionTableName)

	_, err := dm.db.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

func getVersion(dm *DatabaseManager) (*Migration, error) {
	err := createVersionTable(dm)
	if err != nil {
		return nil, err
	}

	version := &Migration{
		Id: MigrationID,
	}

	query := fmt.Sprintf("SELECT migration_version FROM %s WHERE id = $1", VersionTableName)
	err = dm.db.QueryRow(query, version.Id).
		Scan(&version.MigrationVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			version.MigrationVersion = "0.0"
		} else {
			return nil, err
		}
	}
	return version, nil
}

func updateVersion(dm *DatabaseManager, v *Migration) error {
	if strings.HasPrefix(v.MigrationVersion, "0.") {
		return createVersionEntry(dm, v)
	}

	query := fmt.Sprintf("UPDATE %s SET migration_version = $1 WHERE id = $2;", VersionTableName)
	_, err := dm.db.Exec(query,
		MigrationVersion, &v.Id)
	if err != nil {
		return err
	}
	return nil
}

func createVersionEntry(dm *DatabaseManager, v *Migration) error {
	query := fmt.Sprintf("INSERT INTO %s (id, migration_version) VALUES ($1, $2);", VersionTableName)
	_, err := dm.db.Exec(query,
		&v.Id, MigrationVersion)
	if err != nil {
		return err
	}
	return nil
}
