// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"strconv"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

type kprobeOptions struct {
	DisableKprobeMulti bool
}

type uprobeOptions struct {
	DisableUprobeMulti bool
}

type kopt struct {
	set func(val string, options *kprobeOptions) error
}

type uopt struct {
	set func(val string, options *uprobeOptions) error
}

// Allowed kprobe options
var kopts = map[string]kopt{
	option.KeyDisableKprobeMulti: kopt{
		set: func(str string, options *kprobeOptions) (err error) {
			options.DisableKprobeMulti, err = strconv.ParseBool(str)
			return err
		},
	},
}

func getKprobeOptions(specs []v1alpha1.OptionSpec) (*kprobeOptions, error) {
	options := &kprobeOptions{}

	for _, spec := range specs {
		opt, ok := kopts[spec.Name]
		if ok {
			if err := opt.set(spec.Value, options); err != nil {
				return nil, fmt.Errorf("failed to set option %s: %s", spec.Name, err)
			}
			logger.GetLogger().Infof("Set option %s = %s", spec.Name, spec.Value)
		}
	}

	return options, nil
}

// Allowed kprobe options
var uopts = map[string]uopt{
	option.KeyDisableUprobeMulti: uopt{
		set: func(str string, options *uprobeOptions) (err error) {
			options.DisableUprobeMulti, err = strconv.ParseBool(str)
			return err
		},
	},
}

func getUprobeOptions(specs []v1alpha1.OptionSpec) (*uprobeOptions, error) {
	options := &uprobeOptions{}

	for _, spec := range specs {
		opt, ok := uopts[spec.Name]
		if ok {
			if err := opt.set(spec.Value, options); err != nil {
				return nil, fmt.Errorf("failed to set option %s: %s", spec.Name, err)
			}
			logger.GetLogger().Infof("Set option %s = %s", spec.Name, spec.Value)
		}
	}

	return options, nil
}
