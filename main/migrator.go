package main

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
)

func MigrateFileToDB(c *Config) error {
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

	dbManager, err := NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName, &c.dbParams)
	if err != nil {
		return err
	}

	err = migrateIdentities(dbManager, identities)
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

		exists, err := dm.ExistsPrivateKey(id.Uid)
		if err != nil {
			return err
		}
		if exists {
			log.Warnf("%s: identity already exists in database", id.Uid)
		}

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
			return err
		}
	}

	return dm.CloseTransaction(tx, Commit)
}
