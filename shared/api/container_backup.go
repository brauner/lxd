package api

import "time"

// ContainerBackupsPost represents the fields available for a new LXD container backup
type ContainerBackupsPost struct {
	Name             string `json:"name" yaml:"name"`
	ExpiryDate       int64  `json:"expiry" yaml:"expiry"`
	ContainerOnly    bool   `json:"container_only" yaml:"container_only"`
	OptimizedStorage bool   `json:"optimized_storage" yaml:"optimized_storage"`
}

// ContainerBackup represents a LXD container backup
type ContainerBackup struct {
	Name             string    `json:"name" yaml:"name"`
	CreationDate     time.Time `json:"creation_date" yaml:"creation_date"`
	ExpiryDate       time.Time `json:"expiry_date" yaml:"expiry_date"`
	ContainerOnly    bool      `json:"container_only" yaml:"container_only"`
	OptimizedStorage bool      `json:"optimized_storage" yaml:"optimized_storage"`
}

// ContainerBackupPost represents the fields available for the renaming of a
// container backup
type ContainerBackupPost struct {
	Name string `json:"name" yaml:"name"`
}

// ContainerBackupExport represents an exported LXD container
type ContainerBackupExport struct {
	Data []byte `json:"data" yaml:"data"`
}
