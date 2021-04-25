/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARR    ANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"

	osrename "github.com/jbenet/go-os-rename"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "check version",
}

var checkLatestVersionCmd = &cobra.Command{
	Use:   "check",
	Short: "Check to see if you're running the latest version",
	Run: func(cmd *cobra.Command, args []string) {
		latest_version, err := http.GetLatestVersion()
		if err != nil {
			log.Fatalf("error while checking for latest version: %v", err)
		}
		if latest_version != version {
			binary_path := os.Args[0]
			fmt.Printf("You're running version %s\n\n", version)
			fmt.Printf("There is a newer version available (%s)!\n", latest_version)
			fmt.Printf("Please upgrade:\n%s version upgrade\n", binary_path)
		} else {
			fmt.Printf("You are up to date!\n")
			fmt.Printf("You're running version %s\n", version)
		}
	},
}
var upgradeVersionCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "upgrade the latest version",
	Run: func(cmd *cobra.Command, args []string) {
		binary_path, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		latest_version, err := http.GetLatestVersion()
		if err != nil {
			log.Fatalf("error while checking for latest version: %v", err)
		}
		if latest_version != version {
			fmt.Printf("Upgrading %s to version %s\n", binary_path, latest_version)
		} else {
			fmt.Printf("You are up to date already :)\n")
			return
		}

		checksum, latest, err := http.GetLatestBinary(runtime.GOOS, runtime.GOARCH)
		if latest == nil {
			log.Fatalf("Error while downloading latest version %v", err)
		}
		local_checksum := fmt.Sprintf("%x", sha256.Sum256(latest))
		if checksum != local_checksum {
			log.Fatalf(`Checksum error: Checksum of downloaded binary, doesn't match published checksum
            published checksum: %s
            downloaded binary checksum: %s`, checksum, local_checksum)
		}

		tmpfile, err := ioutil.TempFile("", "mysocketctl-"+latest_version)
		if err != nil {
			log.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			log.Fatal(err)
		}

		defer os.Remove(tmpfile.Name())

		err = ioutil.WriteFile(tmpfile.Name(), latest, 0644)
		if err != nil {
			log.Fatalf("Error while writing new file: %v", err)
		}
		tmpfile.Close()
		if err := os.Chmod(tmpfile.Name(), 0755); err != nil {
			log.Fatalln(err)
		}

		if runtime.GOOS == "windows" {
			// 1) first remove potential old files
			bakfile := binary_path + ".bak"
			_ = os.Remove(bakfile)

			// 2) then move the current file to .bak
			e := osrename.Rename(binary_path, bakfile)
			if e != nil {
				log.Fatal(e)
			}
			// 3) move tmp file naar current binary
			e = osrename.Rename(tmpfile.Name(), binary_path)
			if e != nil {
				log.Fatal(e)
			}

		} else {
			e := os.Rename(tmpfile.Name(), binary_path)
			if e != nil {
				log.Fatal(e)
			}
		}
		fmt.Printf("Upgrade completed\n")
	},
}

func init() {
	versionCmd.AddCommand(checkLatestVersionCmd)
	versionCmd.AddCommand(upgradeVersionCmd)
	rootCmd.AddCommand(versionCmd)
}
