// Copyright 2020 Istio Authors
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

package translate

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"istio.io/istio/operator/pkg/util"
)

var (
	testDataDir string
	repoRootDir string
)

func init() {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	repoRootDir = filepath.Join(wd, "../..")
	testDataDir = filepath.Join(wd, "testdata/icp-iop")
}

func TestTranslateYAMLTree(t *testing.T) {
	tests := []struct {
		desc string
	}{
		{
			desc: "default",
		},
		{
			desc: "gateways",
		},
		{
			desc: "addons",
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			inPath := filepath.Join(testDataDir, "input", tt.desc+".yaml")
			outPath := filepath.Join(testDataDir, "output", tt.desc+".yaml")

			translations, err := ReadICPtoIOPTranslations(filepath.Join(repoRootDir, "data/translateConfig/translate-ICP-IOP-1.5.yaml"))
			if err != nil {
				t.Fatal(err)
			}

			icp, err := readFile(inPath)
			if err != nil {
				t.Fatal(err)
			}

			got, err := ICPToIOP(icp, translations)
			if err != nil {
				t.Fatal(err)
			}

			if refreshGoldenFiles() {
				t.Logf("Refreshing golden file for %s", outPath)
				if err := ioutil.WriteFile(outPath, []byte(got), 0644); err != nil {
					t.Error(err)
				}
			}

			want, err := readFile(outPath)
			if err != nil {
				t.Fatal(err)
			}

			if !util.IsYAMLEqual(got, want) {
				t.Errorf("%s got:\n%s\n\nwant:\n%s\nDiff:\n%s\n", tt.desc, got, want, util.YAMLDiff(got, want))
			}
		})
	}
}

func refreshGoldenFiles() bool {
	return os.Getenv("UPDATE_GOLDENS") == "true"
}

func readFile(path string) (string, error) {
	b, err := ioutil.ReadFile(path)
	return string(b), err
}
