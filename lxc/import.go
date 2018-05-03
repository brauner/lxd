package main

import (
	"bytes"
	"io"
	"os"

	"github.com/lxc/lxd/shared/i18n"
	"github.com/spf13/cobra"

	cli "github.com/lxc/lxd/shared/cmd"
)

type cmdImport struct {
	global *cmdGlobal
}

func (c *cmdImport) Command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = i18n.G("import [<remote>:] <backup file>")
	cmd.Short = i18n.G("Import container backup")
	cmd.Long = cli.FormatSection(i18n.G("Description"), i18n.G(
		`Import backups of containers including their snapshots.`))
	cmd.Example = cli.FormatSection("", i18n.G(
		`lxc export u1 backup0.tar.xz
    Create the backup.

lxc import backup0
    Import the backup.`))

	cmd.RunE = c.Run

	return cmd
}

func (c *cmdImport) Run(cmd *cobra.Command, args []string) error {
	// Sanity checks
	exit, err := c.global.CheckArgs(cmd, args, 1, 2)
	if exit {
		return err
	}

	// Parse remote
	remote := ""
	if len(args) > 1 {
		remote = args[0]
	}

	resources, err := c.global.ParseServers(remote)
	if err != nil {
		return err
	}

	resource := resources[0]

	file, err := os.Open(args[len(args)-1])
	if err != nil {
		return nil
	}
	defer file.Close()

	var buf bytes.Buffer
	io.Copy(&buf, file)

	op, err := resource.server.CreateContainerFromBackup(buf.Bytes())
	if err != nil {
		return err
	}

	return op.Wait()
}
