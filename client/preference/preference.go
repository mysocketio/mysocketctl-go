package preference

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Read() (*Data, error) {
	data := NewData()

	pathToFile, err := filePath()
	if err != nil {
		return data, fmt.Errorf("failed to get preference file path: %w", err)
	}

	if _, err := os.Stat(pathToFile); os.IsNotExist(err) {
		// file does not exist, but we don't want to error.
		// we'll just return an empty preference
		// First time this get's called, the file will be created on write.
		return data, nil
	}

	jsonFile, err := os.Open(pathToFile)
	if err != nil {
		return data, fmt.Errorf("failed to open %s: %w", pathToFile, err)
	}
	if err := json.NewDecoder(jsonFile).Decode(&data); err != nil {
		return data, fmt.Errorf("failed to decode %s: %w", pathToFile, err)
	}

	return data, nil
}

func Write(data *Data) error {
	pathToFile, err := filePath()
	if err != nil {
		return fmt.Errorf("failed to get preference file path: %w", err)
	}
	jsonFile, err := os.Create(pathToFile)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to create %s: %w", pathToFile, err)
	}
	encoder := json.NewEncoder(jsonFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode %s: %w", pathToFile, err)
	}

	return nil
}

func filePath() (string, error) {
	prefix, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config dir: %w", err)
	}

	configDir := filepath.Join(prefix, "mysocket")
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.Mkdir(configDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create config dir: %w", err)
		}
	}

	return filepath.Join(prefix, "mysocket", "preference.json"), nil
}

func CreateOrUpdate(orgID, orgSubdomain string) error {
	if orgID == "" {
		return errors.New("WARNING: org ID is empty")
	}

	pref, err := Read()
	if err != nil {
		return fmt.Errorf("WARNING: could not read preference file: %w", err)
	}

	orgPref := pref.Org(orgID)
	orgPref.Subdomain = orgSubdomain
	pref.SetOrg(orgPref)

	if err := Write(pref); err != nil {
		return fmt.Errorf("WARNING: could not update preference file: %w", err)
	}

	return nil
}
