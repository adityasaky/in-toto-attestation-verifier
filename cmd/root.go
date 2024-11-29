package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/attestation-verifier/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:  "attestation-verifier",
	RunE: verify,
}

var (
	layoutPath      string
	attestationsDir string
	parametersPath  string
	withResolver    bool
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(
		&layoutPath,
		"layout",
		"l",
		"",
		"Layout to use for verification",
	)

	rootCmd.Flags().StringVarP(
		&attestationsDir,
		"attestations-directory",
		"a",
		"",
		"Directory to load attestations from",
	)

	rootCmd.Flags().StringVar(
		&parametersPath,
		"substitute-parameters",
		"",
		"Path to JSON file containing key-value string pairs for parameter substitution in the layout",
	)

	rootCmd.Flags().BoolVarP(
		&withResolver,
		"with-rd-resolver",
		"r",
		false,
		"Enable resource descriptor (RD) resolver needed for cross-attestation checks",
	)

	rootCmd.MarkFlagRequired("layout")
	rootCmd.MarkFlagRequired("attestations-directory")
}

func verify(cmd *cobra.Command, args []string) error {
	layout, err := verifier.LoadLayout(layoutPath)
	if err != nil {
		return err
	}

	dirEntries, err := os.ReadDir(attestationsDir)
	if err != nil {
		return err
	}

	attestations := map[string]*dsse.Envelope{}
	for _, e := range dirEntries {
		name := e.Name()
		ab, err := os.ReadFile(filepath.Join(attestationsDir, name))
		if err != nil {
			return err
		}
		// attestation := &attestationv1.Statement{}
		// if err := json.Unmarshal(ab, attestation); err != nil {
		// 	return err
		// }
		// encodedBytes, err := cjson.EncodeCanonical(attestation)
		// if err != nil {
		// 	return err
		// }
		// envelope := &dsse.Envelope{
		// 	Payload:     base64.StdEncoding.EncodeToString(encodedBytes),
		// 	PayloadType: "application/vnd.in-toto+json",
		// }
		envelope := &dsse.Envelope{}
		if err := json.Unmarshal(ab, envelope); err != nil {
			return err
		}

		attestations[strings.TrimSuffix(name, ".json")] = envelope
	}

	parameters := map[string]string{}
	if len(parametersPath) > 0 {
		contents, err := os.ReadFile(parametersPath)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(contents, &parameters); err != nil {
			return err
		}
	}

	return verifier.Verify(layout, attestations, parameters, withResolver)
}
