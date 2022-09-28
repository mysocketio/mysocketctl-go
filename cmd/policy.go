package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/term"
)

// policyCmd represents the policy command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage your global Policies",
}

// policysListCmd represents the policy ls command
var policysListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List your Policies",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := http.NewClient()

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		policiesPath := "policies"
		if perPage != 0 {
			if page == 0 {
				page = 1
			}
			policiesPath += fmt.Sprintf("?page_size=%d", perPage)
			policiesPath += fmt.Sprintf("&page=%d", page)
		} else {
			if page != 0 {
				policiesPath += fmt.Sprintf("?page_size=%d", 100)
				policiesPath += fmt.Sprintf("&page=%d", page)
			}
		}

		policys := []models.Policy{}
		err = client.Request("GET", policiesPath, &policys, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Name", "Description", "# Sockets"})

		for _, s := range policys {
			var socketIDs string

			for _, p := range s.SocketIDs {
				if socketIDs == "" {
					socketIDs = socketIDs + ", " + p
				}

			}

			t.AppendRow(table.Row{s.Name, s.Description, len(s.SocketIDs)})
		}
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

// policyDeleteCmd represents the policy delete command
var policyDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a policy",
	Run: func(cmd *cobra.Command, args []string) {
		if policyName == "" {
			log.Fatalf("error: invalid policy name")
		}

		policy, err := findPolicyByName(policyName)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err = client.Request("DELETE", "policy/"+policy.ID, nil, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		fmt.Println("Policy deleted")
	},
}

// policyAttachCmd represents the policy delete command
var policyAttachCmd = &cobra.Command{
	Use:   "attach",
	Short: "Attach a policy",
	Run: func(cmd *cobra.Command, args []string) {
		if policyName == "" {
			log.Fatalf("error: invalid policy name")
		}

		if socketID == "" {
			log.Fatalf("error: invalid socket id")
		}

		policy, err := findPolicyByName(policyName)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		body := models.AddSocketToPolicyRequest{
			Actions: []models.PolicyActionUpdateRequest{{
				ID:     socketID,
				Action: "add",
			}},
		}

		err = client.Request("PUT", "policy/"+policy.ID+"/socket", nil, body)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		fmt.Println("Policy attached to socket")
	},
}

// policyDettachCmd represents the policy delete command
var policyDettachCmd = &cobra.Command{
	Use:   "detach",
	Short: "Detach a policy",
	Run: func(cmd *cobra.Command, args []string) {
		if policyName == "" {
			log.Fatalf("error: invalid policy name")
		}

		if socketID == "" {
			log.Fatalf("error: invalid socket id")
		}

		policy, err := findPolicyByName(policyName)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		body := models.AddSocketToPolicyRequest{
			Actions: []models.PolicyActionUpdateRequest{{
				ID:     socketID,
				Action: "remove",
			}},
		}

		err = client.Request("PUT", "policy/"+policy.ID+"/socket", nil, body)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		fmt.Println("Policy detached from socket")
	},
}

// policyShowCmd represents the policy show command
var policyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a policy",
	Run: func(cmd *cobra.Command, args []string) {
		if policyName == "" {
			log.Fatalf("error: invalid policy name")
		}

		policy, err := findPolicyByName(policyName)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Name", "Description", "# Sockets"})
		t.AppendRow(table.Row{policy.Name, policy.Description, len(policy.SocketIDs)})
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())

		jsonData, err := json.MarshalIndent(policy.PolicyData, "", "  ")
		if err != nil {
			fmt.Printf("could not marshal json: %s\n", err)
			return
		}

		t = table.NewWriter()
		t.AppendHeader(table.Row{"Policy Data"})
		t.AppendRow(table.Row{string(jsonData)})
		t.SetStyle(table.StyleLight)

		fmt.Printf("%s\n", t.Render())

	},
}

// policyAddCmd represents the policy show command
var policyAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Create a policy",
	Run: func(cmd *cobra.Command, args []string) {
		if policyName == "" {
			log.Fatalf("error: invalid policy name")
		}

		fpath := os.TempDir() + "/policyName.json"
		f, err := os.Create(fpath)
		if err != nil {
			fmt.Printf("could not create a policy file %s\n", err)
			return
		}
		f.Close()

		file, err := os.OpenFile(fpath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Printf("could not create a policy file %s\n", err)
			return
		}

		file.WriteString(policyTemplate())
		file.Close()

		c := exec.Command(defaultEnvEditor(), fpath)
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		if err := (term.TTY{In: os.Stdin, TryDev: true}).Safe(c.Run); err != nil {
			if err, ok := err.(*exec.Error); ok {
				if err.Err == exec.ErrNotFound {
					fmt.Printf("unable to launch the editor")
					return
				}
			}
			fmt.Printf("there was a problem with the editor")
			return
		}
		jsonFile, err := os.Open(fpath)
		if err != nil {
			fmt.Printf("could not open policy file %s\n", err)
			return
		}
		defer jsonFile.Close()
		byteValue, err := ioutil.ReadAll(jsonFile)
		if err != nil {
			fmt.Printf("could not open policy file %s\n", err)
			return
		}

		var policyData models.PolicyData

		json.Unmarshal(byteValue, &policyData)

		req := models.CreatePolicyRequest{
			Name:        policyName,
			PolicyData:  policyData,
			Description: policyDescription,
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		err = client.Request("POST", "policies", nil, req)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		fmt.Println("Policy created")
	},
}

func defaultEnvEditor() string {
	editor := os.Getenv("EDITOR")

	if len(editor) == 0 {
		editor = "vi"
	}
	if !strings.Contains(editor, " ") {
		return []string{editor}[0]
	}
	if !strings.ContainsAny(editor, "\"'\\") {
		return strings.Split(editor, " ")[0]
	}
	return editor
}

func findPolicyByName(name string) (models.Policy, error) {
	client, err := http.NewClient()

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	policiesPath := "policies/find?name=" + name
	policy := models.Policy{}

	err = client.Request("GET", policiesPath, &policy, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	return policy, nil
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policysListCmd)
	policyCmd.AddCommand(policyDeleteCmd)
	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyAttachCmd)
	policyCmd.AddCommand(policyDettachCmd)
	policyCmd.AddCommand(policyAddCmd)

	policysListCmd.Flags().Int64Var(&perPage, "per_page", 100, "The number of results to return per page.")
	policysListCmd.Flags().Int64Var(&page, "page", 0, "The page of results to return.")

	policyDeleteCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyDeleteCmd.MarkFlagRequired("name")

	policyShowCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyShowCmd.MarkFlagRequired("name")

	policyAttachCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyAttachCmd.MarkFlagRequired("name")
	policyAttachCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	policyAttachCmd.MarkFlagRequired("socket_id")

	policyDettachCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyDettachCmd.MarkFlagRequired("name")
	policyDettachCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	policyDettachCmd.MarkFlagRequired("socket_id")

	policyAddCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")
	policyAddCmd.MarkFlagRequired("name")
	policyAddCmd.Flags().StringVarP(&policyDescription, "description", "d", "", "Policy Description")

}

func policyTemplate() string {
	return `{
	"version": "v1",
	"action": [
		"database",
		"ssh",
		"http"
	],
	"condition": {
		"who": {
		"email": [
			"example@border0.com"
		],
		"domain": [
			"example.com"
		]
		},
		"where": {
			"allowed_ip": [],
			"country": [],
			"country_not": []
		},
		"when": {
			"after": "1970-01-01T00:00:00Z",
			"before": null,
			"time_of_day_after": "00:00:00 UTC",
			"time_of_day_before": "23:59:59 UTC"
		}
	}
}`
}
