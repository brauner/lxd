package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os/exec"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/lxc/lxd/lxd/state"
	"github.com/lxc/lxd/shared/api"
	"github.com/pkg/errors"
)

var ErrMissingIndexFile = errors.New("missing index.yaml")

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

type backupInfo struct {
	Name       string   `json:"name" yaml:"name"`
	Backend    string   `json:"backend" yaml:"backend"`
	Privileged bool     `json:"privileged" yaml:"privileged"`
	Snapshots  []string `json:"snapshots,omitempty" yaml:"snapshots,omitempty"`
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

// Dump dumps the container including its snapshots.
func (b *backup) Dump() ([]byte, error) {
	ourStart, err := b.container.StorageStart()
	if err != nil {
		return nil, err
	}
	if ourStart {
		defer b.container.StorageStop()
	}

	data, err := b.container.Storage().ContainerBackupDump(*b)
	if err != nil {
		return nil, err
	}

	return data, nil
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

func getBackupInfo(r io.Reader) (*backupInfo, error) {
	var buf bytes.Buffer
	cmd := exec.Command("unxz", "-")
	cmd.Stdin = r
	cmd.Stdout = &buf
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return nil, err
		}

		if hdr.Name == "backup/index.yaml" {
			result := backupInfo{}
			err = yaml.NewDecoder(tr).Decode(&result)
			if err != nil {
				return nil, err
			}
			return &result, nil
		}
	}

	return nil, ErrMissingIndexFile
}
