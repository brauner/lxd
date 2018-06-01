package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/lxc/lxd/shared"
	"github.com/lxc/lxd/shared/eagain"
)

/*
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char* advance_arg(bool required);
extern void attach_userns(int pid);
extern int dosetns(int pid, char *nstype);

void forkproxy() {
	int childPid, cmdline, connect_pid, fdnum, append, listen_pid, logfd, ret;
	char *cur = NULL, *logPath = NULL, *pidPath = NULL, *listen_addr = NULL;
	FILE *logFile = NULL, *pidFile = NULL;

	// /proc/self/fd/<num> (14 (path) + 21 (int64) + 1 (null))
	char fdpath[36];

	// Get the pid
	cur = advance_arg(false);
	if (cur == NULL || (strcmp(cur, "--help") == 0 || strcmp(cur, "--version") == 0 || strcmp(cur, "-h") == 0))
		return;
	listen_pid = atoi(cur);

	// Get the arguments
	listen_addr = advance_arg(true);
	connect_pid = atoi(advance_arg(true));
	advance_arg(true);
	fdnum = atoi(advance_arg(true));
	append = atoi(advance_arg(true));
	logPath = advance_arg(true);
	pidPath = advance_arg(true);

	if (append == 0)
		logFile = fopen(logPath, "w+");
	else
		logFile = fopen(logPath, "a+");
	if (logFile == NULL) {
		_exit(EXIT_FAILURE);
	}

	logfd = fileno(logFile);
	if (logfd < 0)
		_exit(EXIT_FAILURE);

	ret = dup2(logfd, STDOUT_FILENO);
	if (ret < 0) {
		fprintf(logFile, "Failed to redirect STDOUT to logfile: %s\n", strerror(errno));
		_exit(EXIT_FAILURE);
	}

	ret = dup2(logfd, STDERR_FILENO);
	if (ret < 0) {
		fprintf(logFile, "Failed to redirect STDERR to logfile: %s\n", strerror(errno));
		_exit(EXIT_FAILURE);
	}
	fclose(logFile);

	pidFile = fopen(pidPath, "w+");
	if (pidFile == NULL) {
		fprintf(stderr, "Failed to create pid file for proxy daemon: %s\n", strerror(errno));
		_exit(EXIT_FAILURE);
	}

	childPid = fork();
	if (childPid < 0) {
		fprintf(stderr, "Failed to fork proxy daemon: %s\n", strerror(errno));
		_exit(EXIT_FAILURE);
	}

	if (childPid != 0) {
		fprintf(pidFile, "%d", childPid);
		fclose(pidFile);
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		_exit(EXIT_SUCCESS);
	}

	ret = setsid();
	if (ret < 0) {
		fprintf(stderr, "Failed to setsid in proxy daemon: %s\n", strerror(errno));
		_exit(EXIT_FAILURE);
	}

	// Cannot pass through -1 to runCommand since it is interpreted as a flag
	if (fdnum == 0)
		fdnum = -1;

	ret = snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fdnum);
	if (ret < 0 || (size_t)ret >= sizeof(fdpath)) {
		fprintf(stderr, "Failed to format file descriptor path\n");
		_exit(EXIT_FAILURE);
	}

	// Join the listener ns if not already setup
	if (access(fdpath, F_OK) < 0) {
		// Attach to the user namespace of the listener
		attach_userns(listen_pid);

		// Attach to the network namespace of the listener
		ret = dosetns(listen_pid, "net");
		if (ret < 0) {
			fprintf(stderr, "Failed setns to listener network namespace: %s\n", strerror(errno));
			_exit(EXIT_FAILURE);
		}

		// Attach to the mount namespace of the listener
		ret = dosetns(listen_pid, "mnt");
		if (ret < 0) {
			fprintf(stderr, "Failed setns to listener mount namespace: %s\n", strerror(errno));
			_exit(EXIT_FAILURE);
		}
	} else {
		// Attach to the user namespace of the listener
		attach_userns(connect_pid);

		// Attach to the network namespace of the listener
		ret = dosetns(connect_pid, "net");
		if (ret < 0) {
			fprintf(stderr, "Failed setns to listener network namespace: %s\n", strerror(errno));
			_exit(EXIT_FAILURE);
		}

		// Attach to the mount namespace of the listener
		ret = dosetns(connect_pid, "mnt");
		if (ret < 0) {
			fprintf(stderr, "Failed setns to listener mount namespace: %s\n", strerror(errno));
			_exit(EXIT_FAILURE);
		}
	}
}
*/
import "C"

type cmdForkproxy struct {
	global *cmdGlobal
}

type proxyAddress struct {
	connType string
	addr     string
	abstract bool
}

func (c *cmdForkproxy) Command() *cobra.Command {
	// Main subcommand
	cmd := &cobra.Command{}
	cmd.Use = "forkproxy <listen PID> <listen address> <connect PID> <connect address> <fd> <reexec> <log path> <pid path>"
	cmd.Short = "Setup network connection proxying"
	cmd.Long = `Description:
  Setup network connection proxying

  This internal command will spawn a new proxy process for a particular
  container, connecting one side to the host and the other to the
  container.
`
	cmd.RunE = c.Run
	cmd.Hidden = true

	return cmd
}

func (c *cmdForkproxy) Run(cmd *cobra.Command, args []string) error {
	// Sanity checks
	if len(args) != 8 {
		cmd.Help()

		if len(args) == 0 {
			return nil
		}

		return fmt.Errorf("Missing required arguments")
	}

	// Only root should run this
	if os.Geteuid() != 0 {
		return fmt.Errorf("This must be run as root")
	}
	// Get all our arguments
	listenPid := args[0]
	listenAddr := args[1]
	connectPid := args[2]
	connectAddr := args[3]

	fd := -1
	if args[4] != "0" {
		fd, _ = strconv.Atoi(args[4])
	}

	// Check where we are in initialization
	fmt.Println(fd)
	if fd < 0 {
		fmt.Printf("Listening on %s in %s, forwarding to %s from %s\n", listenAddr, listenPid, connectAddr, connectPid)

		file, err := getListenerFile(listenAddr)
		if err != nil {
			return err
		}
		defer file.Close()

		listenerFd := file.Fd()

		err = shared.AbstractUnixSendFd(3, int(listenerFd))
		if err != nil {
			return err
		}
		syscall.Close(3)
		return nil
	}

	// Re-create listener from fd
	listenFile := os.NewFile(uintptr(fd), "listener")
	listener, err := net.FileListener(listenFile)
	if err != nil {
		return fmt.Errorf("Failed to re-assemble listener: %v", err)
	}

	// Handle SIGTERM which is sent when the proxy is to be removed
	terminate := false
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)

	// Wait for SIGTERM and close the listener in order to exit the loop below
	go func() {
		<-sigs
		terminate = true
		listener.Close()
	}()

	cAddr := parseAddr(connectAddr)
	lAddr := parseAddr(listenAddr)

	if cAddr.connType == "unix" && !cAddr.abstract {
		// Create socket
		file, err := getListenerFile(fmt.Sprintf("unix:%s", cAddr.addr))
		if err != nil {
			return err
		}

		defer func() {
			file.Close()
			os.Remove(cAddr.addr)
		}()
	}

	if lAddr.connType == "unix" && !lAddr.abstract {
		defer os.Remove(lAddr.addr)
	}

	fmt.Printf("Starting to proxy\n")

	// begin proxying
	for {
		// Accept a new client
		srcConn, err := listener.Accept()
		if err != nil {
			if terminate {
				break
			}

			fmt.Printf("error: Failed to accept new connection: %v\n", err)
			continue
		}
		fmt.Printf("Accepted a new connection\n")

		// Connect to the target
		dstConn, err := getDestConn(connectAddr)
		if err != nil {
			fmt.Printf("error: Failed to connect to target: %v\n", err)
			srcConn.Close()
			continue
		}

		if cAddr.connType == "unix" && lAddr.connType == "unix" {
			// Handle OOB if both src and dst are using unix sockets
			go relay(srcConn.(*net.UnixConn), dstConn.(*net.UnixConn))
			go relay(dstConn.(*net.UnixConn), srcConn.(*net.UnixConn))
		} else {
			go io.Copy(eagain.Writer{Writer: srcConn}, eagain.Reader{Reader: dstConn})
			go io.Copy(eagain.Writer{Writer: dstConn}, eagain.Reader{Reader: srcConn})
		}
	}

	fmt.Println("Stopping proxy")

	return nil
}

func getListenerFile(listenAddr string) (os.File, error) {
	fields := strings.SplitN(listenAddr, ":", 2)
	addr := strings.Join(fields[1:], "")

	listener, err := net.Listen(fields[0], addr)
	if err != nil {
		return os.File{}, fmt.Errorf("Failed to listen on %s: %v", addr, err)
	}

	file := &os.File{}
	switch listener.(type) {
	case *net.TCPListener:
		tcpListener := listener.(*net.TCPListener)
		file, err = tcpListener.File()
	case *net.UnixListener:
		unixListener := listener.(*net.UnixListener)
		file, err = unixListener.File()
	}
	if err != nil {
		return os.File{}, fmt.Errorf("Failed to get file from listener: %v", err)
	}

	return *file, nil
}

func getDestConn(connectAddr string) (net.Conn, error) {
	fields := strings.SplitN(connectAddr, ":", 2)
	addr := strings.Join(fields[1:], "")
	return net.Dial(fields[0], addr)
}

func relay(src *net.UnixConn, dst *net.UnixConn) {
	dataBuf := make([]byte, 4096)
	oobBuf := make([]byte, 4096)

	for {
		// Read from the source
		sData, sOob, _, _, err := src.ReadMsgUnix(dataBuf, oobBuf)
		if err != nil {
			fmt.Printf("Disconnected during read: %v\n", err)
			src.Close()
			dst.Close()
			return
		}

		var fds []int
		if sOob > 0 {
			entries, err := syscall.ParseSocketControlMessage(oobBuf[:sOob])
			if err != nil {
				fmt.Printf("Failed to parse control message: %v\n", err)
				src.Close()
				dst.Close()
				return
			}

			for _, msg := range entries {
				fds, err = syscall.ParseUnixRights(&msg)
				if err != nil {
					fmt.Printf("Failed to get fd list for control message: %v\n", err)
					src.Close()
					dst.Close()
					return
				}
			}
		}

		// Send to the destination
		tData, tOob, err := dst.WriteMsgUnix(dataBuf[:sData], oobBuf[:sOob], nil)
		if err != nil {
			fmt.Printf("Disconnected during write: %v\n", err)
			src.Close()
			dst.Close()
			return
		}

		if sData != tData || sOob != tOob {
			fmt.Printf("Some data got lost during transfer, disconnecting.")
			src.Close()
			dst.Close()
			return
		}

		// Close those fds we received
		if fds != nil {
			for _, fd := range fds {
				err := syscall.Close(fd)
				if err != nil {
					fmt.Printf("Failed to close fd %d: %v\n", fd, err)
					src.Close()
					dst.Close()
					return
				}
			}
		}
	}
}

func parseAddr(addr string) *proxyAddress {
	fields := strings.SplitN(addr, ":", 2)
	return &proxyAddress{
		connType: fields[0],
		addr:     fields[1],
		abstract: strings.HasPrefix(fields[1], "@"),
	}
}
