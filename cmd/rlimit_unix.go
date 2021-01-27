// +build !windows

package cmd

import (
	"fmt"
	"log"
	"runtime"
	"syscall"
)

func SetRlimit() {
	// check open file limit
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Println("Error Getting Rlimit ", err)
	}

	if runtime.GOOS == "darwin" {
		if rLimit.Cur < 10240 {
			rLimit.Cur = 10240
		}
	} else {
		if rLimit.Cur < rLimit.Max {
			rLimit.Cur = rLimit.Max
		}
	}

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Println("Error Setting Rlimit ", err)
	}

}
