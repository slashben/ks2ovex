package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/openvex/go-vex/pkg/vex"
)

func loadJsonFileAsVulnerabilityManifest(fileName string) (v1beta1.VulnerabilityManifest, error) {
	var vuln v1beta1.VulnerabilityManifest
	vulnJsonFile, err := os.Open(fileName)
	if err != nil {
		return vuln, err
	}
	defer vulnJsonFile.Close()

	vulnRawJson, err := io.ReadAll(vulnJsonFile)
	if err != nil {
		return vuln, err
	}

	err = json.Unmarshal(vulnRawJson, &vuln)
	if err != nil {
		return vuln, err
	}

	return vuln, nil
}

func main() {
	// Get single input argument as a json file path
	if len(os.Args) != 3 {
		fmt.Printf("Please provide a file path to the vulnerability json files: %s <path-to-vulnerability-json-file> <path-to-filtered-vulnerability-json-file>\n", os.Args[0])
		os.Exit(1)
	}
	vuln, err := loadJsonFileAsVulnerabilityManifest(os.Args[1])
	if err != nil {
		fmt.Printf("Error loading vulnerability json file: %s\n", err)
		os.Exit(1)
	}

	filteredVuln, err := loadJsonFileAsVulnerabilityManifest(os.Args[2])
	if err != nil {
		fmt.Printf("Error loading filtered vulnerability json file: %s\n", err)
		os.Exit(1)
	}

	// Check that the vuln is indeed unfiltered
	if vuln.Labels["kubescape.io/context"] != "non-filtered" {
		fmt.Printf("Error: the vulnerability json file is not unfiltered\n")
		os.Exit(1)
	}

	// Check that the filteredVuln is indeed filtered
	if filteredVuln.Labels["kubescape.io/context"] != "filtered" {
		fmt.Printf("Error: the vulnerability json file is not filtered\n")
		os.Exit(1)
	}

	vulnImage := vuln.Annotations["kubescape.io/image-id"]
	filteredImage := strings.TrimPrefix(filteredVuln.Annotations["kubescape.io/image-id"], "docker-pullable://")

	// Make sure it is the same image
	if vulnImage != filteredImage {
		fmt.Printf("Error: the vulnerability json files are not for the same image (%s != %s)\n", vulnImage, filteredImage)
		os.Exit(1)
	}

	// Yes, we have a valid Vulnerability structs :)
	// Now we create a VEX document from the Vulnerability struct

	doc := vex.New()
	doc.Author = "Kubescape vulnerability scanner"
	doc.AuthorRole = "Senior open source project :)"

	// Loop over the Vulnerability struct and add each vulnerability to the VEX document
	for _, v := range vuln.Spec.Payload.Matches {
		var aliases []vex.VulnerabilityID
		for _, alias := range v.RelatedVulnerabilities {
			aliases = append(aliases, vex.VulnerabilityID(alias.ID))
		}

		identifiers := make(map[vex.IdentifierType]string)
		identifiers[vex.PURL] = v.Artifact.PURL
		for _, cpe := range v.Artifact.CPEs {
			if strings.HasPrefix(cpe, "cpe:2.3") {
				identifiers[vex.CPE23] = cpe
			} else if strings.HasPrefix(cpe, "cpe:2.2") {
				identifiers[vex.CPE22] = cpe
			}
		}

		doc.Statements = append(doc.Statements, vex.Statement{
			Vulnerability: vex.Vulnerability{
				ID:          v.Vulnerability.DataSource,
				Name:        vex.VulnerabilityID(v.Vulnerability.ID),
				Description: v.Vulnerability.Description,
				Aliases:     aliases,
			},

			Products: []vex.Product{
				{
					Component: vex.Component{
						ID:          vuln.Annotations["kubescape.io/image-id"],
						Identifiers: identifiers,
					},
				},
			},

			Status:          vex.StatusNotAffected,
			Justification:   vex.VulnerableCodeNotPresent,
			ImpactStatement: "Vulnerable component is not loaded into the memory",
		})
	}

	// Now change the status of the filtered vulnerabilities to "Affected"
	for _, v := range filteredVuln.Spec.Payload.Matches {
		for i, s := range doc.Statements {
			if s.Vulnerability.Name == vex.VulnerabilityID(v.Vulnerability.ID) {
				doc.Statements[i].Status = vex.StatusAffected
				doc.Statements[i].Justification = ""
				doc.Statements[i].ImpactStatement = "Vulnerable component is loaded into the memory"
			}
		}
	}

	// Generate a canonical identifier for the VEX document:
	doc.GenerateCanonicalID()

	// Output the document to stdout:
	doc.ToJSON(os.Stdout)

	os.Exit(0)
}
