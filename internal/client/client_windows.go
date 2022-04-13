//go:build windows
// +build windows

package client

import (
	"golang.org/x/crypto/ssh"
)

// MonWinCh does nothing for now on windows
func MonWinCh(session *ssh.Session, fd uintptr) {
	return
}
