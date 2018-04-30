package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"os/exec"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/lxc/lxd/lxd/db"
	"github.com/lxc/lxd/lxd/state"
	"github.com/lxc/lxd/shared"
	"github.com/lxc/lxd/shared/api"
	"github.com/pkg/errors"
)

var ErrMissingIndexFile = errors.New("missing index.yaml")
var ErrMissingBackupFile = errors.New("missing backup.yaml")

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

func getBackupStoragePool(s *state.State, r io.Reader) (storage, error) {
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

		if hdr.Name == "backup/container/backup.yaml" {
			backup := backupFile{}
			err = yaml.NewDecoder(tr).Decode(&backup)
			if err != nil {
				return nil, err
			}
			return storagePoolInit(s, backup.Pool.Name)
		}
	}

	return nil, ErrMissingBackupFile
}

// fixBackupStoragePool changes the pool information in the backup.yaml. This
// is done only if the provided pool doesn't exist. In this case, the pool of
// the default profile will be used.
func fixBackupStoragePool(c *db.Cluster, b backupInfo) error {
	// Get the default profile
	_, profile, err := c.ProfileGet("default")
	if err != nil {
		return err
	}

	_, v, err := shared.GetRootDiskDevice(profile.Devices)
	if err != nil {
		return err
	}

	// Get the default's profile pool
	_, pool, err := c.StoragePoolGet(v["pool"])
	if err != nil {
		return err
	}

	f := func(path string) error {
		// Read in the backup.yaml file.
		backup, err := slurpBackupFile(path)
		if err != nil {
			return err
		}

		// Change the pool in the backup.yaml
		backup.Pool = pool
		backup.Container.Devices["root"]["pool"] = "default"

		file, err := os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()

		data, err := yaml.Marshal(&backup)
		if err != nil {
			return err
		}

		_, err = file.Write(data)
		if err != nil {
			return err
		}

		return nil
	}

	err = f(shared.VarPath("storage-pools", pool.Name, "containers", b.Name, "backup.yaml"))
	if err != nil {
		return err
	}

	for _, snap := range b.Snapshots {
		err = f(shared.VarPath("storage-pools", pool.Name, "snapshots", b.Name, snap,
			"backup.yaml"))
		if err != nil {
			return err
		}
	}
	return nil
}
