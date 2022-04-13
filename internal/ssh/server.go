package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
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

		pubKey := s.PublicKey()
		cert, ok := pubKey.(*gossh.Certificate)
		if !ok {
			log.Printf("could not get user certificate")
			return
		}

		log.Printf("new ssh session for %s (as user %s)\n", cert.KeyId, s.User())

		uid, _ := strconv.ParseUint(user.Uid, 10, 32)
		gid, _ := strconv.ParseUint(user.Gid, 10, 32)

		var cmd exec.Cmd
		if len(s.Command()) > 0 {
			cmd.Path = shell
			if runtime.GOOS == "windows" {
				cmd.Args = []string{shell, "/C", s.RawCommand()}
			} else {
				cmd.Args = []string{shell, "-c", s.RawCommand()}
			}
		} else {
			cmd.Path = shell
			if runtime.GOOS != "windows" {
				cmd.Args = []string{"-" + filepath.Base(shell)}
			}
		}

		cmd.Env = []string{
			"LANG=en_US.UTF-8",
			"HOME=" + user.HomeDir,
			"USER=" + user.Username,
			"SHELL=" + shell,
		}

		cmd.Dir = user.HomeDir

		execCmd(s, cmd, uid, gid)

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
