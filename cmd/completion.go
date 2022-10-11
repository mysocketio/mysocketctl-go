package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:                   "completion [bash|zsh|fish|powershell]",
	Short:                 "Generate completion script",
	Long:                  completionUsage(),
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			zshHead := "#compdef border0\ncompdef _border0 border0\n"
			os.Stdout.Write([]byte(zshHead))

			cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			cmd.Root().GenPowerShellCompletion(os.Stdout)
		}
	},
}

func completionUsage() string {
	brewPrefix := "/usr/local"
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("brew", "--prefix").CombinedOutput()
		trimmed := strings.TrimSpace(string(out))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: cannot execute `brew --prefix` %s, %s\n\n", trimmed, err)
		} else {
			brewPrefix = trimmed
		}
	}
	return `To load completions:

Bash:

  $ source <(border0 completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ border0 completion bash > /etc/bash_completion.d/border0
  # macOS:
  $ border0 completion bash > ` + brewPrefix + `/etc/bash_completion.d/border0

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ border0 completion zsh > "${fpath[1]}/_border0"

  # You will need to start a new shell for this setup to take effect.

fish:

  $ border0 completion fish | source

  # To load completions for each session, execute once:
  $ border0 completion fish > ~/.config/fish/completions/border0.fish

PowerShell:

  PS> border0 completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> border0 completion powershell > border0.ps1
  # and source this file from your PowerShell profile.
`
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
