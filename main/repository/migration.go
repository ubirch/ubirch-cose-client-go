package repository

import (
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/sirupsen/logrus"

)

func RunMigrations(scriptsPath, connURL, schema string) error {
	log := logrus.WithFields(logrus.Fields{})
	m, err := migrate.New(
		scriptsPath, fmt.Sprintf("%s&search_path=%s", connURL, schema))
	if err != nil {
		return err
	}
	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return err
	}
	if err == migrate.ErrNoChange {
		//log.Info("No new migration scripts")
		return nil
	}
	log.Info("Migration scipts run successfully")
	return nil
}