package main

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lxc/lxd/shared/api"
	cli "github.com/lxc/lxd/shared/cmd"
	"github.com/lxc/lxd/shared/i18n"
)

type cmdExport struct {
	global *cmdGlobal

	flagContainerOnly    bool
	flagOptimizedStorage bool
}

func (c *cmdExport) Command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = i18n.G("export [<remote>:]<container> [target] [--container-only] [--optimized-storage]")
	cmd.Short = i18n.G("Export container backup")
	cmd.Long = cli.FormatSection(i18n.G("Description"), i18n.G(
		`Export backups of containers including their snapshots.`))
	cmd.Example = cli.FormatSection("", i18n.G(
		`lxc export u1 backup0.tar.xz
    Create the backup.

lxc import backup0
    Export the backup.`))

	cmd.RunE = c.Run
	cmd.Flags().BoolVar(&c.flagContainerOnly, "container-only", false,
		i18n.G("Whether or not to only backup the container (without snapshots)"))
	cmd.Flags().BoolVar(&c.flagOptimizedStorage, "optimized-storage", false,
		i18n.G("Use send command for containers and backups (only Btrfs and ZFS)"))

	return cmd
}

func (c *cmdExport) Run(cmd *cobra.Command, args []string) error {
	conf := c.global.conf

	// Sanity checks
	exit, err := c.global.CheckArgs(cmd, args, 1, 2)
	if exit {
		return err
	}

	// Connect to LXD
	remote, name, err := conf.ParseRemote(args[0])
	if err != nil {
		return err
	}

	d, err := conf.GetContainerServer(remote)
	if err != nil {
		return err
	}

	req := api.ContainerBackupsPost{
		Name:             "",
		ExpiryDate:       1800, // 30 minutes
		ContainerOnly:    c.flagContainerOnly,
		OptimizedStorage: c.flagOptimizedStorage,
	}

	op, err := d.CreateContainerBackup(name, req)
	if err != nil {
		return err
	}

	// Wait until backup is done
	err = op.Wait()
	if err != nil {
		return err
	}

	// Get name of backup
	backupName := strings.TrimPrefix(op.Get().Resources["backups"][0],
		"/1.0/backups/")

	defer func() {
		// Delete backup after we're done
		op, _ = d.DeleteContainerBackup(name, backupName)
		op.Wait()
	}()

	// Export tarball
	export, _, err := d.GetContainerBackupExport(name, backupName)
	if err != nil {
		return err
	}

	var targetName string
	if len(args) > 1 {
		targetName = args[1]
	} else {
		targetName = "backup.tar.xz"
	}

	file, err := os.Create(targetName)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(export.Data)
	if err != nil {
		return err
	}

	return nil
}
