package main

import (
	"time"

	"github.com/lxc/lxd/lxd/state"
	"github.com/lxc/lxd/shared/api"
)

// backup represents a container backup.
type backup struct {
	state     *state.State
	container container

	// Properties
	id               int
	name             string
	creationDate     time.Time
	expiryDate       time.Time
	containerOnly    bool
	optimizedStorage bool
}

// Rename renames a container backup.
func (b *backup) Rename(newName string) error {
	ourStart, err := b.container.StorageStart()
	if err != nil {
		return err
	}
	if ourStart {
		defer b.container.StorageStop()
	}

	// Rename the database entry
	err = b.state.Cluster.ContainerBackupRename(b.Name(), newName)
	if err != nil {
		return err
	}

	// Rename the directories and files
	err = b.container.Storage().ContainerBackupRename(*b, newName)
	if err != nil {
		return err
	}

	return nil
}

// Delete removes a container backup.
func (b *backup) Delete() error {
	ourStart, err := b.container.StorageStart()
	if err != nil {
		return err
	}
	if ourStart {
		defer b.container.StorageStop()
	}

	// Remove the database record
	err = b.state.Cluster.ContainerBackupRemove(b.Name())
	if err != nil {
		return err
	}

	// Delete backup from storage
	err = b.container.Storage().ContainerBackupDelete(b.Name())
	if err != nil {
		return err
	}

	return nil
}

func (b *backup) Render() interface{} {
	return &api.ContainerBackup{
		Name:             b.name,
		CreationDate:     b.creationDate,
		ExpiryDate:       b.expiryDate,
		ContainerOnly:    b.containerOnly,
		OptimizedStorage: b.optimizedStorage,
	}
}

func (b *backup) Id() int {
	return b.id
}

func (b *backup) Name() string {
	return b.name
}

func (b *backup) CreationDate() time.Time {
	return b.creationDate
}

func (b *backup) ExpiryDate() time.Time {
	return b.expiryDate
}

func (b *backup) ContainerOnly() bool {
	return b.containerOnly
}

func (b *backup) OptimizedStorage() bool {
	return b.optimizedStorage
}
