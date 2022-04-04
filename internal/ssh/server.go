package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/creack/pty"
)

func newServer(ca string) *ssh.Server {
	ssh.Handle(func(s ssh.Session) {
		user, err := user.Lookup(s.User())
		if err != nil {
			log.Printf("could not find user: %s", err)
			return
		}

		shell, err := getShell(user)
		if err != nil {
			log.Printf("could not get user shell: %s", err)
			return
		}

		log.Printf("new ssh session for user %s\n", s.User())

		uid, _ := strconv.ParseUint(user.Uid, 10, 32)
		gid, _ := strconv.ParseUint(user.Gid, 10, 32)

		var cmd exec.Cmd
		if len(s.Command()) > 0 {
			cmd.Path = shell
			cmd.Args = []string{shell, "-c", s.RawCommand()}
		} else {
			cmd.Path = shell
			cmd.Args = []string{"-" + filepath.Base(shell)}
		}

		cmd.Env = []string{
			"LANG=en_US.UTF-8",
			"HOME=" + user.HomeDir,
			"USER=" + user.Username,
			"SHELL=" + shell,
		}

		cmd.Dir = user.HomeDir

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
	})

	return &ssh.Server{
		Version: "Mysocketctl-ssh-server",
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			pubCert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca))
			if err != nil {
				log.Fatalf("ERROR parsing public cert: %s", err)
			}

			cert, ok := key.(*gossh.Certificate)
			if !ok {
				log.Printf("ERROR: key is not a cert")
				return false
			}

			if !bytes.Equal(cert.SignatureKey.Marshal(), pubCert.Marshal()) {
				log.Println("can not validate certificate")
				return false
			}

			var certChecker gossh.CertChecker

			err = certChecker.CheckCert("mysocket_ssh_signed", cert)
			if err != nil {
				log.Println("failed validating the certificate")
				return false
			}

			return true
		},
	}
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func getShell(user *user.User) (string, error) {
	switch runtime.GOOS {
	case "linux", "openbsd", "freebsd":
		out, err := exec.Command("getent", "passwd", user.Uid).Output()
		if err != nil {
			return "", err
		}

		ent := strings.Split(strings.TrimSuffix(string(out), "\n"), ":")
		return ent[6], nil
	case "darwin":
		dir := "Local/Default/Users/" + user.Username
		out, err := exec.Command("dscl", "localhost", "-read", dir, "UserShell").Output()
		if err != nil {
			return "", err
		}

		re := regexp.MustCompile("UserShell: (/[^ ]+)\n")
		matched := re.FindStringSubmatch(string(out))
		shell := matched[1]
		if shell == "" {
			return "", fmt.Errorf("invalid output: %s", string(out))
		}

		return shell, nil
	case "windows":
		consoleApp := os.Getenv("COMSPEC")
		if consoleApp == "" {
			consoleApp = "cmd.exe"
		}

		return consoleApp, nil
	}

	return "", errors.New("unsupported platform")
}
