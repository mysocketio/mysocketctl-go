//go:build !windows
// +build !windows

package ssh

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func execCmd(s ssh.Session, cmd exec.Cmd, uid, gid uint64) {

	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))

		f, err := pty.StartWithAttrs(&cmd, &pty.Winsize{}, &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:         uint32(uid),
				Gid:         uint32(gid),
				NoSetGroups: true,
			},
			Setsid:  true,
			Setctty: true,
		})
		if err != nil {
			log.Println(err)
			return
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, s)
		}()
		io.Copy(s, f)

		cmd.Wait()
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:         uint32(uid),
				Gid:         uint32(gid),
				NoSetGroups: true,
			},
			Setsid: true,
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("failed to set stdout: %v\n", err)
			return
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			log.Printf("failed to set stderr: %v\n", err)
			return
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			log.Printf("failed to set stdin: %v\n", err)
			return
		}

		wg := &sync.WaitGroup{}
		wg.Add(2)
		if err = cmd.Start(); err != nil {
			log.Printf("failed to start command %v\n", err)
			return
		}
		go func() {
			defer stdin.Close()
			if _, err := io.Copy(stdin, s); err != nil {
				log.Printf("failed to write to session %s\n", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := io.Copy(s, stdout); err != nil {
				log.Printf("failed to write to stdout %s\n", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := io.Copy(s.Stderr(), stderr); err != nil {
				log.Printf("failed to write from stderr%s\n", err)
			}
		}()

		wg.Wait()
		cmd.Wait()

	}
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
