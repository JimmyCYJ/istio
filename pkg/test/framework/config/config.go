// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"go.uber.org/atomic"
	"gopkg.in/yaml.v3"

	"istio.io/istio/pkg/test/scopes"
	"istio.io/istio/pkg/test/util/file"
)

const prefix = "istio.test"

var (
	configFilePath string
	parsed         atomic.Bool
)

func init() {
	flag.StringVar(&configFilePath, "istio.test.config", "", "Path to test framework config file")
}

type Value interface {
	flag.Value
	SetConfig(Map) error
}

func Parsed() bool {
	return flag.Parsed() && parsed.Load()
}

// Parse overrides any unset command line flags beginning with "istio.test" with values provided
// from a YAML file.
func Parse() {
	defer func() {
		parsed.Store(true)
	}()
	if !flag.Parsed() {
		flag.Parse()
	}
	if configFilePath == "" {
		return
	}

	cfg, err := readConfig()
	if err != nil {
		scopes.Framework.Error(err)
		return
	}
	set := map[string]struct{}{}
	flag.Visit(func(f *flag.Flag) {
		set[f.Name] = struct{}{}
	})

	flag.VisitAll(func(f *flag.Flag) {
		var err error
		defer func() {
			if err != nil {
				scopes.Framework.Errorf("failed getting %s from config file: %v", f.Name, err)
			}
		}()

		// exclude non-istio flags and flags that were set via command line
		if !strings.HasPrefix(f.Name, prefix) {
			return
		}
		if _, ok := set[f.Name]; ok {
			return
		}

		// grab the map containing the last "." separated key
		keys := strings.Split(f.Name, ".")
		parentPath, key := keys[:len(keys)-1], keys[len(keys)-1]
		parent := cfg
		for _, k := range parentPath {
			parent = parent.Map(k)
			if parent == nil {
				return
			}
		}

		// if we have a Map at the last key, and the registered value implements our custom value, parse via Map
		cfgMap := parent.Map(key)
		cfgValue, isCfgVal := f.Value.(Value)
		if isCfgVal && len(cfgMap) > 0 {
			err = cfgValue.SetConfig(cfgMap)
		} else if v := parent.String(key); v != "" {
			// otherwise parse via string (if-set)
			err = f.Value.Set(v)
		}
	})
}

func readConfig() (Map, error) {
	path, err := file.NormalizePath(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed normalizing config file path %q: %v", configFilePath, err)
	}
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading %s: %v", path, err)
	}
	cfg := Map{}
	if err := yaml.Unmarshal(bytes, cfg); err != nil {
		return nil, fmt.Errorf("failed unmarshalling %s: %v", path, err)
	}
	return cfg, nil
}
