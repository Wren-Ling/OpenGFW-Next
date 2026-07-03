package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apernet/OpenGFW/ruleset"
	"gopkg.in/yaml.v3"
)

type externalFingerprintFile struct {
	Fingerprints ruleset.FingerprintConfig  `yaml:"fingerprints"`
	Suspicious   []ruleset.FingerprintEntry `yaml:"suspicious"`
}

func (c *cliConfig) loadExternalDatasets(configFile string) error {
	baseDir := "."
	if configFile != "" {
		baseDir = filepath.Dir(configFile)
	}
	if err := loadFingerprintSetFiles(baseDir, "ja3", &c.Fingerprints.JA3); err != nil {
		return err
	}
	if err := loadFingerprintSetFiles(baseDir, "ja4", &c.Fingerprints.JA4); err != nil {
		return err
	}
	if err := loadFingerprintSetFiles(baseDir, "quicJa3", &c.Fingerprints.QUICJA3); err != nil {
		return err
	}
	if err := loadFingerprintSetFiles(baseDir, "quicJa4", &c.Fingerprints.QUICJA4); err != nil {
		return err
	}
	return nil
}

func loadFingerprintSetFiles(baseDir, setName string, set *ruleset.FingerprintSet) error {
	for _, file := range set.Files {
		path := file
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		entries, err := readFingerprintEntries(path, setName)
		if err != nil {
			return err
		}
		set.Suspicious = append(set.Suspicious, entries...)
	}
	return nil
}

func readFingerprintEntries(path, setName string) ([]ruleset.FingerprintEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fingerprint file %s: %w", path, err)
	}
	var entries []ruleset.FingerprintEntry
	if err := yaml.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
		return entries, nil
	}
	var file externalFingerprintFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse fingerprint file %s: %w", path, err)
	}
	if len(file.Suspicious) > 0 {
		return file.Suspicious, nil
	}
	set := fingerprintSetByName(file.Fingerprints, setName)
	return set.Suspicious, nil
}

func fingerprintSetByName(config ruleset.FingerprintConfig, setName string) ruleset.FingerprintSet {
	switch setName {
	case "ja3":
		return config.JA3
	case "ja4":
		return config.JA4
	case "quicJa3":
		return config.QUICJA3
	case "quicJa4":
		return config.QUICJA4
	default:
		return ruleset.FingerprintSet{}
	}
}
