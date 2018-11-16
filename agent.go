//
// Copyright (c) 2017-2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	"github.com/kata-containers/agent/pkg/uevent"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/opencontainers/runtime-spec/specs-go"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

const (
	procCgroups = "/proc/cgroups"
	meminfo     = "/proc/meminfo"
)

var (
	// cgroup fs is mounted at /sys/fs when systemd is the init process
	sysfsDir                     = "/sys"
	cgroupPath                   = sysfsDir + "/fs/cgroup"
	cgroupCpusetPath             = cgroupPath + "/cpuset"
	cgroupMemoryPath             = cgroupPath + "/memory"
	cgroupMemoryUseHierarchyPath = cgroupMemoryPath + "/memory.use_hierarchy"
	cgroupMemoryUseHierarchyMode = os.FileMode(0400)

	// Set by the build
	seccompSupport string

	// Set to the context that should be used for tracing gRPC calls.
	grpcContext context.Context
)

var initRootfsMounts = []initMount{
	{"proc", "proc", "/proc", []string{"nosuid", "nodev", "noexec"}},
	{"sysfs", "sysfs", sysfsDir, []string{"nosuid", "nodev", "noexec"}},
	{"devtmpfs", "dev", "/dev", []string{"nosuid"}},
	{"tmpfs", "tmpfs", "/dev/shm", []string{"nosuid", "nodev"}},
	{"devpts", "devpts", "/dev/pts", []string{"nosuid", "noexec"}},
}

type process struct {
	sync.RWMutex

	id          string
	process     libcontainer.Process
	stdin       *os.File
	stdout      *os.File
	stderr      *os.File
	consoleSock *os.File
	termMaster  *os.File
	epoller     *epoller
	exitCodeCh  chan int
	sync.Once
	stdinClosed bool
}

type container struct {
	sync.RWMutex

	id              string
	initProcess     *process
	container       libcontainer.Container
	config          configs.Config
	processes       map[string]*process
	mounts          []string
	useSandboxPidNs bool
	ctx             context.Context
}

type sandboxStorage struct {
	refCount int
}

type sandbox struct {
	sync.RWMutex
	ctx context.Context

	id          string
	hostname    string
	containers  map[string]*container
	channel     channel
	network     network
	wg          sync.WaitGroup
	sharedPidNs namespace
	mounts      []string
	subreaper   reaper
	server      *grpc.Server

	// Set when server needs to be shut down
	shutdown chan bool

	pciDeviceMap      map[string]string
	deviceWatchers    map[string](chan string)
	sharedUTSNs       namespace
	sharedIPCNs       namespace
	guestHooks        *specs.Hooks
	guestHooksPresent bool
	running           bool
	noPivotRoot       bool
	sandboxPidNs      bool
	storages          map[string]*sandboxStorage
}

var agentFields = logrus.Fields{
	"name":   agentName,
	"pid":    os.Getpid(),
	"source": "agent",
}

var agentLog = logrus.WithFields(agentFields)

// version is the agent version. This variable is populated at build time.
var version = "unknown"

var debug = false

// tracing enables opentracing support
var tracing = false

// Associate agent traces with runtime traces
var collatedTrace = false

// if true, coredump when an internal error occurs or a fatal signal is received
var crashOnError = false

// This is the list of file descriptors we can properly close after the process
// has been started. When the new process is exec(), those file descriptors are
// duplicated and it is our responsibility to close them since we have opened
// them.
func (p *process) closePostStartFDs() {
	if p.process.Stdin != nil {
		p.process.Stdin.(*os.File).Close()
	}

	if p.process.Stdout != nil {
		p.process.Stdout.(*os.File).Close()
	}

	if p.process.Stderr != nil {
		p.process.Stderr.(*os.File).Close()
	}

	if p.process.ConsoleSocket != nil {
		p.process.ConsoleSocket.Close()
	}

	if p.consoleSock != nil {
		p.consoleSock.Close()
	}
}

// This is the list of file descriptors we can properly close after the process
// has exited. These are the remaining file descriptors that we have opened and
// are no longer needed.
func (p *process) closePostExitFDs() {
	if p.termMaster != nil {
		p.termMaster.Close()
	}

	if p.stdin != nil {
		p.stdin.Close()
	}

	if p.stdout != nil {
		p.stdout.Close()
	}

	if p.stderr != nil {
		p.stderr.Close()
	}

	if p.epoller != nil {
		p.epoller.sockR.Close()
	}
}

func (c *container) trace(name string) (opentracing.Span, context.Context) {
	if c.ctx == nil {
		agentLog.WithField("type", "bug").Error("trace called before context set")
		c.ctx = context.Background()
	}

	return trace(c.ctx, "container", name)
}

func (c *container) setProcess(process *process) {
	c.Lock()
	c.processes[process.id] = process
	c.Unlock()
}

func (c *container) deleteProcess(execID string) {
	span, _ := c.trace("deleteProcess")
	span.SetTag("exec-id", execID)
	defer span.Finish()

	c.Lock()
	delete(c.processes, execID)
	c.Unlock()
}

func (c *container) removeContainer() error {
	span, _ := c.trace("removeContainer")
	defer span.Finish()

	// This will terminates all processes related to this container, and
	// destroy the container right after. But this will error in case the
	// container in not in the right state.
	if err := c.container.Destroy(); err != nil {
		return err
	}

	return removeMounts(c.mounts)
}

func (c *container) getProcess(execID string) (*process, error) {
	c.RLock()
	defer c.RUnlock()

	proc, exist := c.processes[execID]
	if !exist {
		return nil, grpcStatus.Errorf(codes.NotFound, "Process %s not found (container %s)", execID, c.id)
	}

	return proc, nil
}

func (s *sandbox) trace(name string) (opentracing.Span, context.Context) {
	if s.ctx == nil {
		agentLog.WithField("type", "bug").Error("trace called before context set")
		s.ctx = context.Background()
	}

	span, ctx := trace(s.ctx, "sandbox", name)

	span.SetTag("sandbox", s.id)

	return span, ctx
}

// setSandboxStorage sets the sandbox level reference
// counter for the sandbox storage.
// This method also returns a boolean to let
// callers know if the storage already existed or not.
// It will return true if storage is new.
//
// It's assumed that caller is calling this method after
// acquiring a lock on sandbox.
func (s *sandbox) setSandboxStorage(path string) bool {
	if _, ok := s.storages[path]; !ok {
		sbs := &sandboxStorage{refCount: 1}
		s.storages[path] = sbs
		return true
	}
	sbs := s.storages[path]
	sbs.refCount++
	return false
}

// waitForServerStopRequest blocks, waiting for the gRPC server itself to request
// that it be shut down.
func (s *sandbox) waitForServerStopRequest() {
	span, _ := s.trace("waitForServerStopRequest")
	defer span.Finish()

	// Wait for the server to report completion.
	<-s.shutdown
}

// scanGuestHooks will search the given guestHookPath
// for any OCI hooks
func (s *sandbox) scanGuestHooks(guestHookPath string) {
	span, _ := s.trace("scanGuestHooks")
	span.SetTag("guest-hook-path", guestHookPath)
	defer span.Finish()

	fieldLogger := agentLog.WithField("oci-hook-path", guestHookPath)
	fieldLogger.Info("Scanning guest filesystem for OCI hooks")

	s.guestHooks.Prestart = findHooks(guestHookPath, "prestart")
	s.guestHooks.Poststart = findHooks(guestHookPath, "poststart")
	s.guestHooks.Poststop = findHooks(guestHookPath, "poststop")

	if len(s.guestHooks.Prestart) > 0 || len(s.guestHooks.Poststart) > 0 || len(s.guestHooks.Poststop) > 0 {
		s.guestHooksPresent = true
	} else {
		fieldLogger.Warn("Guest hooks were requested but none were found")
	}
}

// addGuestHooks will add any guest OCI hooks that were
// found to the OCI spec
func (s *sandbox) addGuestHooks(spec *specs.Spec) {
	span, _ := s.trace("addGuestHooks")
	defer span.Finish()

	if spec == nil {
		return
	}

	if spec.Hooks == nil {
		spec.Hooks = &specs.Hooks{}
	}

	spec.Hooks.Prestart = append(spec.Hooks.Prestart, s.guestHooks.Prestart...)
	spec.Hooks.Poststart = append(spec.Hooks.Poststart, s.guestHooks.Poststart...)
	spec.Hooks.Poststop = append(spec.Hooks.Poststop, s.guestHooks.Poststop...)
}

// unSetSandboxStorage will decrement the sandbox storage
// reference counter. If there aren't any containers using
// that sandbox storage, this method will remove the
// storage reference from the sandbox and return 'true, nil' to
// let the caller know that they can clean up the storage
// related directories by calling removeSandboxStorage
//
// It's assumed that caller is calling this method after
// acquiring a lock on sandbox.
func (s *sandbox) unSetSandboxStorage(path string) (bool, error) {
	span, _ := s.trace("unSetSandboxStorage")
	span.SetTag("path", path)
	defer span.Finish()

	if sbs, ok := s.storages[path]; ok {
		sbs.refCount--
		// If this sandbox storage is not used by any container
		// then remove it's reference
		if sbs.refCount < 1 {
			delete(s.storages, path)
			return true, nil
		}
		return false, nil
	}
	return false, grpcStatus.Errorf(codes.NotFound, "Sandbox storage with path %s not found", path)
}

// removeSandboxStorage removes the sandbox storage if no
// containers are using that storage.
//
// It's assumed that caller is calling this method after
// acquiring a lock on sandbox.
func (s *sandbox) removeSandboxStorage(path string) error {
	span, _ := s.trace("removeSandboxStorage")
	span.SetTag("path", path)
	defer span.Finish()

	err := removeMounts([]string{path})
	if err != nil {
		return grpcStatus.Errorf(codes.Unknown, "Unable to unmount sandbox storage path %s", path)
	}
	err = os.RemoveAll(path)
	if err != nil {
		return grpcStatus.Errorf(codes.Unknown, "Unable to delete sandbox storage path %s", path)
	}
	return nil
}

// unsetAndRemoveSandboxStorage unsets the storage from sandbox
// and if there are no containers using this storage it will
// remove it from the sandbox.
//
// It's assumed that caller is calling this method after
// acquiring a lock on sandbox.
func (s *sandbox) unsetAndRemoveSandboxStorage(path string) error {
	span, _ := s.trace("unsetAndRemoveSandboxStorage")
	span.SetTag("path", path)
	defer span.Finish()

	if _, ok := s.storages[path]; ok {
		removeSbs, err := s.unSetSandboxStorage(path)
		if err != nil {
			return err
		}

		if removeSbs {
			if err := s.removeSandboxStorage(path); err != nil {
				return err
			}
		}

		return nil
	}
	return grpcStatus.Errorf(codes.NotFound, "Sandbox storage with path %s not found", path)
}

func (s *sandbox) getContainer(id string) (*container, error) {
	s.RLock()
	defer s.RUnlock()

	ctr, exist := s.containers[id]
	if !exist {
		return nil, grpcStatus.Errorf(codes.NotFound, "Container %s not found", id)
	}

	return ctr, nil
}

func (s *sandbox) setContainer(ctx context.Context, id string, ctr *container) {
	// Update the context. This is required since the function is called
	// from by gRPC functions meaning we must use the latest context
	// available.
	s.ctx = ctx

	span, _ := s.trace("setContainer")
	span.SetTag("id", id)
	span.SetTag("container", ctr.id)
	defer span.Finish()

	s.Lock()
	s.containers[id] = ctr
	s.Unlock()
}

func (s *sandbox) deleteContainer(id string) {
	span, _ := s.trace("deleteContainer")
	span.SetTag("container", id)
	defer span.Finish()

	s.Lock()

	// Find the sandbox storage used by this container
	ctr, exist := s.containers[id]
	if !exist {
		agentLog.WithField("container-id", id).Debug("Container doesn't exist")
	} else {
		// Let's go over the mounts used by this container
		for _, k := range ctr.mounts {
			// Check if this mount is used from sandbox storage
			if _, ok := s.storages[k]; ok {
				if err := s.unsetAndRemoveSandboxStorage(k); err != nil {
					agentLog.WithError(err).Error()
				}
			}
		}
	}

	delete(s.containers, id)
	s.Unlock()
}

func (s *sandbox) getProcess(cid, execID string) (*process, *container, error) {
	if s.running == false {
		return nil, nil, grpcStatus.Error(codes.FailedPrecondition, "Sandbox not started")
	}

	ctr, err := s.getContainer(cid)
	if err != nil {
		return nil, nil, err
	}

	// A container being in stopped state is not a valid reason for not
	// accepting a call to getProcess(). Indeed, we want to make sure a
	// shim can connect after the process has already terminated. Some
	// processes have a very short lifetime and the shim might end up
	// calling into WaitProcess() after this happened. This does not mean
	// we cannot retrieve the output and the exit code from the shim.
	proc, err := ctr.getProcess(execID)
	if err != nil {
		return nil, nil, err
	}

	return proc, ctr, nil
}

func (s *sandbox) readStdio(cid, execID string, length int, stdout bool) ([]byte, error) {
	proc, _, err := s.getProcess(cid, execID)
	if err != nil {
		return nil, err
	}

	var file *os.File
	if proc.termMaster != nil {
		// The process's epoller's run() will return a file descriptor of the process's
		// terminal or one end of its exited pipe. If it returns its terminal, it means
		// there is data needed to be read out or it has been closed; if it returns the
		// process's exited pipe, it means the process has exited and there is no data
		// needed to be read out in its terminal, thus following read on it will read out
		// "EOF" to terminate this process's io since the other end of this pipe has been
		// closed in reap().
		file, err = proc.epoller.run()
		if err != nil {
			return nil, err
		}
	} else {
		if stdout {
			file = proc.stdout
		} else {
			file = proc.stderr
		}
	}

	buf := make([]byte, length)

	bytesRead, err := file.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:bytesRead], nil
}

func (s *sandbox) setupSharedNamespaces(ctx context.Context) error {
	span, _ := trace(ctx, "sandbox", "setupSharedNamespaces")
	defer span.Finish()

	// Set up shared IPC namespace
	ns, err := setupPersistentNs(nsTypeIPC)
	if err != nil {
		return err
	}
	s.sharedIPCNs = *ns

	// Set up shared UTS namespace
	ns, err = setupPersistentNs(nsTypeUTS)
	if err != nil {
		return err
	}
	s.sharedUTSNs = *ns

	return nil
}

func (s *sandbox) unmountSharedNamespaces() error {
	span, _ := s.trace("unmountSharedNamespaces")
	defer span.Finish()

	if err := unix.Unmount(s.sharedIPCNs.path, unix.MNT_DETACH); err != nil {
		return err
	}

	return unix.Unmount(s.sharedUTSNs.path, unix.MNT_DETACH)
}

// setupSharedPidNs will reexec this binary in order to execute the C routine
// defined into pause.go file. The pauseBinArg is very important since that is
// the flag allowing the C function to determine it should run the "pause".
// This pause binary will ensure that we always have the init process of the
// new PID namespace running into the namespace, preventing the namespace to
// be destroyed if other processes are terminated.
func (s *sandbox) setupSharedPidNs() error {
	span, _ := s.trace("setupSharedPidNs")
	defer span.Finish()

	cmd := &exec.Cmd{
		Path: selfBinPath,
		Args: []string{os.Args[0], pauseBinArg},
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID,
	}

	exitCodeCh, err := s.subreaper.start(cmd)
	if err != nil {
		return err
	}

	// Save info about this namespace inside sandbox structure.
	s.sharedPidNs = namespace{
		path:       fmt.Sprintf("/proc/%d/ns/pid", cmd.Process.Pid),
		init:       cmd.Process,
		exitCodeCh: exitCodeCh,
	}

	return nil
}

func (s *sandbox) teardownSharedPidNs() error {
	span, _ := s.trace("teardownSharedPidNs")
	defer span.Finish()

	if !s.sandboxPidNs {
		// We are not in a case where we have created a pause process.
		// Simply clear out the sharedPidNs path.
		s.sharedPidNs.path = ""
		return nil
	}

	// Terminates the "init" process of the PID namespace.
	if err := s.sharedPidNs.init.Kill(); err != nil {
		return err
	}

	// Using helper function wait() to deal with the subreaper.
	osProcess := (*reaperOSProcess)(s.sharedPidNs.init)
	if _, err := s.subreaper.wait(s.sharedPidNs.exitCodeCh, osProcess); err != nil {
		return err
	}

	// Empty the sandbox structure.
	s.sharedPidNs = namespace{}

	return nil
}

// The context parameter is for tracing - although there is a context stored
// in the sandbox object itself, it is necessary to use the provided context
// as this function is run from a goroutine.
func (s *sandbox) listenToUdevEvents(ctx context.Context) {
	fieldLogger := agentLog.WithField("subsystem", "udevlistener")

	uEvHandler, err := uevent.NewHandler()
	if err != nil {
		fieldLogger.Warnf("Error starting uevent listening loop %s", err)
		return
	}
	defer uEvHandler.Close()

	fieldLogger.Infof("Started listening for uevents")

	for {
		uEv, err := uEvHandler.Read()
		if err != nil {
			fieldLogger.Error(err)
			continue
		}

		// We only care about add event
		if uEv.Action != "add" {
			continue
		}

		span, _ := trace(ctx, "udev", "udev event")
		span.SetTag("udev-action", uEv.Action)
		span.SetTag("udev-name", uEv.DevName)
		span.SetTag("udev-path", uEv.DevPath)
		span.SetTag("udev-subsystem", uEv.SubSystem)
		span.SetTag("udev-seqno", uEv.SeqNum)

		fieldLogger = fieldLogger.WithFields(logrus.Fields{
			"uevent-action":    uEv.Action,
			"uevent-devpath":   uEv.DevPath,
			"uevent-subsystem": uEv.SubSystem,
			"uevent-seqnum":    uEv.SeqNum,
			"uevent-devname":   uEv.DevName,
		})

		fieldLogger.Infof("Received add uevent")

		// Check if device hotplug event results in a device node being created.
		if uEv.DevName != "" && strings.HasPrefix(uEv.DevPath, rootBusPath) {
			// Lock is needed to safey read and modify the pciDeviceMap and deviceWatchers.
			// This makes sure that watchers do not access the map while it is being updated.
			s.Lock()

			// Add the device node name to the pci device map.
			s.pciDeviceMap[uEv.DevPath] = uEv.DevName

			// Notify watchers that are interested in the udev event.
			// Close the channel after watcher has been notified.
			for devPCIAddress, ch := range s.deviceWatchers {
				if ch != nil && strings.HasPrefix(uEv.DevPath, filepath.Join(rootBusPath, devPCIAddress)) {
					ch <- uEv.DevName
					close(ch)
					delete(s.deviceWatchers, uEv.DevName)
				}
			}

			s.Unlock()
		} else if onlinePath := filepath.Join(sysfsDir, uEv.DevPath, "online"); strings.HasPrefix(onlinePath, sysfsMemOnlinePath) {
			// Check memory hotplug and online if possible
			if err := ioutil.WriteFile(onlinePath, []byte("1"), 0600); err != nil {
				fieldLogger.WithError(err).Error("failed online device")
			}
		}

		span.Finish()
	}
}

// This loop is meant to be run inside a separate Go routine.
func (s *sandbox) signalHandlerLoop(sigCh chan os.Signal) {
	for sig := range sigCh {
		logger := agentLog.WithField("signal", sig)

		if sig == unix.SIGCHLD {
			if err := s.subreaper.reap(); err != nil {
				logger.WithError(err).Error("failed to reap")
				continue
			}
		}

		nativeSignal, ok := sig.(syscall.Signal)
		if !ok {
			err := errors.New("unknown signal")
			logger.WithError(err).Error("failed to handle signal")
			continue
		}

		if fatalSignal(nativeSignal) {
			logger.Error("received fatal signal")
			die(s.ctx)
		}

		if debug && nonFatalSignal(nativeSignal) {
			logger.Debug("handling signal")
			backtrace()
			continue
		}

		logger.Info("ignoring unexpected signal")
	}
}

func (s *sandbox) setupSignalHandler() error {
	span, _ := s.trace("setupSignalHandler")
	defer span.Finish()

	// Set agent as subreaper
	err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(1), 0, 0, 0)
	if err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 512)
	signal.Notify(sigCh, unix.SIGCHLD)

	for _, sig := range handledSignals() {
		signal.Notify(sigCh, sig)
	}

	go s.signalHandlerLoop(sigCh)

	return nil
}

// getMemory returns a string containing the total amount of memory reported
// by the kernel. The string includes a suffix denoting the units the memory
// is measured in.
func getMemory() (string, error) {
	bytes, err := ioutil.ReadFile(meminfo)
	if err != nil {
		return "", err
	}

	lines := string(bytes)

	for _, line := range strings.Split(lines, "\n") {
		if !strings.HasPrefix(line, "MemTotal") {
			continue
		}

		expectedFields := 2

		fields := strings.Split(line, ":")
		count := len(fields)

		if count != expectedFields {
			return "", fmt.Errorf("expected %d fields, got %d in line %q", expectedFields, count, line)
		}

		if fields[1] == "" {
			return "", fmt.Errorf("cannot determine total memory from line %q", line)
		}

		memTotal := strings.TrimSpace(fields[1])

		return memTotal, nil
	}

	return "", fmt.Errorf("no lines in file %q", meminfo)
}

func getAnnounceFields() (logrus.Fields, error) {
	var deviceHandlers []string
	var storageHandlers []string

	for handler := range deviceHandlerList {
		deviceHandlers = append(deviceHandlers, handler)
	}

	for handler := range storageHandlerList {
		storageHandlers = append(storageHandlers, handler)
	}

	memTotal, err := getMemory()
	if err != nil {
		return logrus.Fields{}, err
	}

	return logrus.Fields{
		"version":          version,
		"device-handlers":  strings.Join(deviceHandlers, ","),
		"storage-handlers": strings.Join(storageHandlers, ","),
		"system-memory":    memTotal,
	}, nil
}

// formatFields converts logrus Fields (containing arbitrary types) into a string slice.
func formatFields(fields logrus.Fields) []string {
	var results []string

	for k, v := range fields {
		value, ok := v.(string)
		if !ok {
			// convert non-string value into a string
			value = fmt.Sprint(v)
		}

		results = append(results, fmt.Sprintf("%s=%q", k, value))
	}

	return results
}

// announce logs details of the agents version and capabilities.
func announce() error {
	announceFields, err := getAnnounceFields()
	if err != nil {
		return err
	}

	if os.Getpid() == 1 {
		fields := formatFields(agentFields)
		extraFields := formatFields(announceFields)

		fields = append(fields, extraFields...)

		fmt.Printf("announce: %s\n", strings.Join(fields, ","))
	} else {
		agentLog.WithFields(announceFields).Info("announce")
	}

	return nil
}

func (s *sandbox) initLogger() error {
	agentLog.Logger.Formatter = &logrus.TextFormatter{DisableColors: true, TimestampFormat: time.RFC3339Nano}

	config := newConfig(defaultLogLevel)
	if err := config.getConfig(kernelCmdlineFile); err != nil {
		agentLog.WithError(err).Warn("Failed to get config from kernel cmdline")
	}

	agentLog.Logger.SetLevel(config.logLevel)

	return announce()
}

func (s *sandbox) initChannel() error {
	span, ctx := s.trace("initChannel")
	defer span.Finish()

	c, err := newChannel(ctx)
	if err != nil {
		return err
	}

	s.channel = c

	return nil
}

// makeUnaryInterceptor creates a function to handle tracing of unary gRPC calls.
// The reason this needs to return a function being that when this function is
// called, the correct context to use for tracing is not available so the
// returned function must query it when called later.
func makeUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(origCtx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		grpcCall := info.FullMethod

		span, ctx := trace(getGRPCContext(), "gRPC", grpcCall)
		span.SetTag("grpc-method-type", "unary")
		defer span.Finish()

		if strings.HasSuffix(grpcCall, "/ReadStdout") || strings.HasSuffix(grpcCall, "/WriteStdin") {
			// Add a tag to allow filtering of those calls dealing
			// input and output. These tend to be very long and
			// being able to filter them out allows the
			// performance of "core" calls to be determined
			// without the "noise" of these calls.
			span.SetTag("api-category", "interactive")
		}

		// Use the context which will provide the correct trace
		// ordering, *NOT* the context provided to this function.
		return handler(ctx, req)
	}
}

// makeStreamInterceptor creates a function to handle tracing of stream-based gRPC calls.
// The reason this needs to return a function being that when this function is
// called, the correct context to use for tracing is not available so the
// returned function must query it when called later.
func makeStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		span, _ := trace(getGRPCContext(), "gRPC", info.FullMethod)
		span.SetTag("grpc-method-type", "stream")
		defer span.Finish()

		return handler(srv, ss)
	}
}

func (s *sandbox) startGRPC() {
	span, ctx := s.trace("startGRPC")
	defer span.Finish()

	grpcImpl := &agentGRPC{
		sandbox: s,
		version: version,
	}

	var grpcServer *grpc.Server

	var serverOpts []grpc.ServerOption

	if tracing {
		if collatedTrace {
			// "collated" tracing (allow agent traces to be
			// associated with runtime-initiated traces.
			tracer := span.Tracer()

			serverOpts = append(serverOpts, grpc.UnaryInterceptor(otgrpc.OpenTracingServerInterceptor(tracer)))
			serverOpts = append(serverOpts, grpc.StreamInterceptor(otgrpc.OpenTracingStreamServerInterceptor(tracer)))
		} else {
			// "isolated" tracing (agent traces are not associated
			// with runtime-initiated traces).
			serverOpts = append(serverOpts, grpc.UnaryInterceptor(makeUnaryInterceptor()))
			serverOpts = append(serverOpts, grpc.StreamInterceptor(makeStreamInterceptor()))
		}
	}

	grpcServer = grpc.NewServer(serverOpts...)

	pb.RegisterAgentServiceServer(grpcServer, grpcImpl)
	pb.RegisterHealthServer(grpcServer, grpcImpl)

	s.server = grpcServer

	s.wg.Add(1)
	go func() {
		var span2 opentracing.Span

		span2, ctx = trace(ctx, "sandbox", "gRPC server (goroutine)")

		defer func() {
			// Mark the span as finished before the waitgroup is
			// completed to ensure the span is reported before the
			// agent exits.
			span2.Finish()

			s.wg.Done()
		}()

		// Ensure the gRPC calls are traced using spans created from
		// the specified context (parent) for correct ordering.
		grpcContext = ctx

		var err error
		for {
			agentLog.Info("agent grpc server starts")

			err = s.channel.setup()
			if err != nil {
				agentLog.WithError(err).Warn("Failed to setup agent grpc channel")
				return
			}

			err = s.channel.wait()
			if err != nil {
				agentLog.WithError(err).Warn("Failed to wait agent grpc channel ready")
				return
			}

			var l net.Listener
			l, err = s.channel.listen()
			if err != nil {
				agentLog.WithError(err).Warn("Failed to create agent grpc listener")
				return
			}

			// l is closed when Serve() returns
			err = grpcServer.Serve(l)
			if err != nil {
				agentLog.WithError(err).Warn("agent grpc server quits")
				return
			}

			err = s.channel.teardown()
			if err != nil {
				agentLog.WithError(err).Warn("agent grpc channel teardown failed")
				return
			}
		}
	}()
}

func getGRPCContext() context.Context {
	if grpcContext != nil {
		return grpcContext
	}

	agentLog.Warnf("Creating gRPC context as none found")

	return context.Background()
}

func (s *sandbox) stopGRPC() {
	span, _ := s.trace("stopGRPC")
	defer span.Finish()

	if s.server != nil {
		s.server.Stop()
		s.server = nil
	}
}

func (s *sandbox) gracefulStopGRPC() {
	span, _ := s.trace("gracefulStopGRPC")
	defer span.Finish()

	if s.server == nil {
		return
	}

	s.server.GracefulStop()
	s.server = nil
}

type initMount struct {
	fstype, src, dest string
	options           []string
}

func getCgroupMounts(cgPath string) ([]initMount, error) {
	f, err := os.Open(cgPath)
	if err != nil {
		return []initMount{}, err
	}
	defer f.Close()

	hasDevicesCgroup := false

	cgroupMounts := []initMount{{"tmpfs", "tmpfs", cgroupPath, []string{"nosuid", "nodev", "noexec", "mode=755"}}}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		fields := strings.Split(text, "\t")

		// #subsys_name    hierarchy       num_cgroups     enabled
		// fields[0]       fields[1]       fields[2]       fields[3]
		cgroup := fields[0]
		if cgroup == "" || cgroup[0] == '#' || (len(fields) > 3 && fields[3] == "0") {
			continue
		}
		if cgroup == "devices" {
			hasDevicesCgroup = true
		}
		cgroupMounts = append(cgroupMounts, initMount{"cgroup", "cgroup",
			filepath.Join(cgroupPath, cgroup), []string{"nosuid", "nodev", "noexec", "relatime", cgroup}})
	}

	if err = scanner.Err(); err != nil {
		return []initMount{}, err
	}

	// refer to https://github.com/opencontainers/runc/blob/v1.0.0-rc5/libcontainer/cgroups/fs/apply_raw.go#L132
	if !hasDevicesCgroup {
		return []initMount{}, err
	}

	cgroupMounts = append(cgroupMounts, initMount{"tmpfs", "tmpfs",
		cgroupPath, []string{"remount", "ro", "nosuid", "nodev", "noexec", "mode=755"}})
	return cgroupMounts, nil
}

func mountToRootfs(m initMount) error {
	if err := os.MkdirAll(m.dest, os.FileMode(0755)); err != nil {
		return err
	}

	if flags, options, err := parseMountFlagsAndOptions(m.options); err != nil {
		return grpcStatus.Errorf(codes.Internal, "Could not parseMountFlagsAndOptions(%v)", m.options)
	} else if err := syscall.Mount(m.src, m.dest, m.fstype, uintptr(flags), options); err != nil {
		return grpcStatus.Errorf(codes.Internal, "Could not mount %v to %v: %v", m.src, m.dest, err)
	}
	return nil
}

func generalMount() error {
	for _, m := range initRootfsMounts {
		if err := mountToRootfs(m); err != nil {
			// dev is already mounted if the rootfs image is used
			if m.src != "dev" {
				return err
			}
			agentLog.WithError(err).WithField("src", m.src).Warnf("Could not mount filesystem")
		}
	}
	return nil
}

func cgroupsMount() error {
	cgroups, err := getCgroupMounts(procCgroups)
	if err != nil {
		return nil
	}
	for _, m := range cgroups {
		if err := mountToRootfs(m); err != nil {
			return err
		}
	}

	// Enable memory hierarchical account.
	// For more information see https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt
	return ioutil.WriteFile(cgroupMemoryUseHierarchyPath, []byte{'1'}, cgroupMemoryUseHierarchyMode)
}

// initAgentAsInit will do the initializations such as setting up the rootfs
// when this agent has been run as the init process.
func initAgentAsInit() error {
	if err := generalMount(); err != nil {
		return err
	}
	if err := cgroupsMount(); err != nil {
		return err
	}
	if err := syscall.Unlink("/dev/ptmx"); err != nil {
		return err
	}
	if err := syscall.Symlink("/dev/pts/ptmx", "/dev/ptmx"); err != nil {
		return err
	}
	syscall.Setsid()
	syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TIOCSCTTY, 1)
	os.Setenv("PATH", "/bin:/sbin/:/usr/bin/:/usr/sbin/")

	return announce()
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			agentLog.WithError(err).Error("init failed")
		}
		panic("--this line should have never been executed, congratulations--")
	}
}

func realMain(ctx context.Context) error {
	var err error
	var showVersion bool

	flag.BoolVar(&showVersion, "version", false, "display program version and exit")

	flag.Parse()

	if showVersion {
		fmt.Printf("%v version %v\n", agentName, version)
		os.Exit(0)
	}

	// Check if this agent has been run as the init process.
	if os.Getpid() == 1 {
		if err = initAgentAsInit(); err != nil {
			panic(fmt.Sprintf("initAgentAsInit() error: %s", err))
		}
	}

	r := &agentReaper{}
	r.init()

	// Initialize unique sandbox structure.
	s := &sandbox{
		containers: make(map[string]*container),
		running:    false,
		// pivot_root won't work for init, see
		// Documention/filesystem/ramfs-rootfs-initramfs.txt
		noPivotRoot:    os.Getpid() == 1,
		subreaper:      r,
		pciDeviceMap:   make(map[string]string),
		deviceWatchers: make(map[string](chan string)),
		storages:       make(map[string]*sandboxStorage),
		shutdown:       make(chan bool),
	}

	if err = s.initLogger(); err != nil {
		agentLog.WithError(err).Error("failed to setup logger")
		os.Exit(1)
	}

	// setup tracing
	tracer, err := createTracer(agentName)
	if err != nil {
		panic(fmt.Sprintf("failed to setup tracing: %v", err))
	}

	// Create the root span (which is .Finish()'d by stopTracing())
	span := tracer.StartSpan("realMain")
	span.SetTag("source", "agent")

	// Associate the root span with the context
	ctx = opentracing.ContextWithSpan(ctx, span)

	// Set the sandbox context now that the context contains the tracing
	// information.
	s.ctx = ctx

	if err = s.setupSignalHandler(); err != nil {
		agentLog.WithError(err).Error("failed to setup signal handler")
		os.Exit(1)
	}

	if err = s.handleLocalhost(); err != nil {
		agentLog.WithError(err).Error("failed to handle localhost")
		os.Exit(1)
	}

	// Check for vsock vs serial. This will fill the sandbox structure with
	// information about the channel.
	if err = s.initChannel(); err != nil {
		agentLog.WithError(err).Error("failed to setup channels")
		os.Exit(1)
	}

	// Start gRPC server
	s.startGRPC()

	go s.listenToUdevEvents(ctx)

	// Wait for the gRPC server to request that it be stopped.
	s.waitForServerStopRequest()

	// Stop the gRPC server.
	s.gracefulStopGRPC()

	// Wait for the goroutine that started the server to end
	s.wg.Wait()

	if tracing {
		// Report any traces before shutdown
		stopTracing(ctx)
	}

	return nil
}

func main() {
	// create a new empty context
	ctx := context.Background()

	defer handlePanic(ctx)

	err := realMain(ctx)
	if err != nil {
		agentLog.WithError(err).Error("agent failed")
		os.Exit(1)
	}

	agentLog.Debug("agent exiting")

	os.Exit(0)
}
