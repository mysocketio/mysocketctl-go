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
			fmt.Printf("ERROR: cannot execute `brew --prefix` %s, %s\n\n", trimmed, err)
		} else {
			brewPrefix = trimmed
		}
	}
	return `To load completions:

Bash:

  $ source <(mysocketctl completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ mysocketctl completion bash > /etc/bash_completion.d/mysocketctl
  # macOS:
  $ mysocketctl completion bash > ` + brewPrefix + `/etc/bash_completion.d/mysocketctl

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ mysocketctl completion zsh > "${fpath[1]}/_mysocketctl"

  # You will need to start a new shell for this setup to take effect.

fish:

  $ mysocketctl completion fish | source

  # To load completions for each session, execute once:
  $ mysocketctl completion fish > ~/.config/fish/completions/mysocketctl.fish

PowerShell:

  PS> mysocketctl completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> mysocketctl completion powershell > mysocketctl.ps1
  # and source this file from your PowerShell profile.
`
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
