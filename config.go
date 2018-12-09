//
// Copyright (c) 2017-2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"strings"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

const (
	optionPrefix       = "agent."
	logLevelFlag       = optionPrefix + "log"
	devModeFlag        = optionPrefix + "devmode"
	traceModeFlag      = optionPrefix + "trace"
	kernelCmdlineFile  = "/proc/cmdline"
	traceValueIsolated = "isolated"
	traceValueCollated = "collated"
)

type agentConfig struct {
	logLevel logrus.Level
}

func newConfig(level logrus.Level) agentConfig {
	return agentConfig{
		logLevel: level,
	}
}

//Get the agent configuration from kernel cmdline
func (c *agentConfig) getConfig(cmdLineFile string) error {
	if cmdLineFile == "" {
		return grpcStatus.Error(codes.FailedPrecondition, "Kernel cmdline file cannot be empty")
	}

	kernelCmdline, err := ioutil.ReadFile(cmdLineFile)
	if err != nil {
		return err
	}

	words := strings.Fields(string(kernelCmdline))
	for _, word := range words {
		if err := c.parseCmdlineOption(word); err != nil {
			agentLog.WithFields(logrus.Fields{
				"error":  err,
				"option": word,
			}).Warn("Failed to parse kernel option")
		}
	}

	return nil
}

//Parse a string that represents a kernel cmdline option
func (c *agentConfig) parseCmdlineOption(option string) error {
	const (
		optionPosition = iota
		valuePosition
		optionSeparator = "="
	)

	if option == devModeFlag {
		crashOnError = true
		debug = true

		return nil
	}

	if option == traceModeFlag {
		enableTracing(false)
		return nil
	}

	split := strings.Split(option, optionSeparator)

	if len(split) < valuePosition+1 {
		return nil
	}

	switch split[optionPosition] {
	case logLevelFlag:
		level, err := logrus.ParseLevel(split[valuePosition])
		if err != nil {
			return err
		}
		c.logLevel = level
		if level == logrus.DebugLevel {
			debug = true
		}
	case traceModeFlag:
		switch split[valuePosition] {
		case traceValueIsolated:
			enableTracing(false)
		case traceValueCollated:
			enableTracing(true)
		}
	default:
		if strings.HasPrefix(split[optionPosition], optionPrefix) {
			return grpcStatus.Errorf(codes.NotFound, "Unknown option %s", split[optionPosition])
		}
	}

	return nil

}

func enableTracing(enableCollatedTrace bool) {
	agentLog.Info("enabling tracing")

	tracing = true

	// Enable in case this generates more trace spans
	debug = true

	collatedTrace = enableCollatedTrace
}
