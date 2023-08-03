package report

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	kubescapeTypes "github.com/anchore/grype/grype/presenter/models"
	"github.com/project-copacetic/copacetic/pkg/types"
)

type KubescapeParser struct{}

func parseKubescapeReport(file string) (*kubescapeTypes.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var ksr kubescapeTypes.Document
	if err = json.Unmarshal(data, &ksr); err != nil {
		return nil, &ErrorUnsupported{err}
	}

	return &ksr, nil
}

func getArchitecture(ksr *kubescapeTypes.Document) (string, error) {
	// Get the architecture value from the "purl" field
	// Example: "purl": "pkg:deb/debian/passwd@1:4.5-1.1?arch=amd64\u0026upstream=shadow\u0026distro=debian-10",

	for i := range ksr.Matches {
		purl := ksr.Matches[i].Artifact.PURL
		purlSplit := strings.Split(purl, "?")
		purlSplit2 := strings.Split(purlSplit[1], "&")
		purlSplit3 := strings.Split(purlSplit2[0], "=")
		architecture := purlSplit3[1]

		if architecture == "all" {
			continue
		}
		return architecture, nil
	}
	return "", errors.New("architecture value not found")
}

func (k *KubescapeParser) Parse(file string) (*types.UpdateManifest, error) {
	// Parse the kubescape scan results
	report, err := parseKubescapeReport(file)
	if err != nil {
		return nil, err
	}

	// Unmarshal function is not able to detect if the report is in the correct format. It returns no error even if the report is in the wrong format.
	// Therefore, we check if the report is in the correct format by parsing the Descriptor Name
	// If the name does not contain grype, then it is not in the correct format, report is marked as unsupported and passed on to the next parser
	if report.Descriptor.Name != "grype" {
		return nil, &ErrorUnsupported{errors.New("report format not supported by kubescape")}
	}

	arch, err := getArchitecture(report)
	if err != nil {
		return nil, err
	}

	updates := types.UpdateManifest{
		OSType:    report.Distro.Name,
		OSVersion: report.Distro.Version,
		Arch:      arch,
	}

	// Check if vulnerability is OS-lvl package & check if vulnerability is fixable
	for i := range report.Matches {
		vuln := &report.Matches[i]
		if vuln.Artifact.Language == "" && vuln.Vulnerability.Fix.State == "fixed" {
			updates.Updates = append(updates.Updates, types.UpdatePackage{Name: vuln.Artifact.Name, Version: vuln.Vulnerability.Fix.Versions[0]})
		}
	}
	return &updates, nil
}
