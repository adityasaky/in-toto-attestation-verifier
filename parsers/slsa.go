package parsers

import (
	"bytes"
	"encoding/json"
	"strings"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/in-toto/attestation-verifier/utils"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func ParseSlsaAttestation(slsa *model.NeighborsNeighborsHasSLSA, pkgPurl string) (*attestationv1.Statement, error) {
	s := &attestationv1.Statement{}
	resultPred := make(map[string]interface{})

	for _, item := range slsa.Slsa.SlsaPredicate {
		keys := strings.Split(item.Key, ".")
		value := item.Value
		currMap := resultPred

		for i, key := range keys {
			if i == len(keys)-1 {
				currMap[key] = value
			} else {
				if _, ok := currMap[key]; !ok {
					currMap[key] = make(map[string]interface{})
				}
				currMap = currMap[key].(map[string]interface{})
			}
		}
	}

	resultPred = ParseMap(resultPred)

	var slsaType string
	if slsa.Slsa.SlsaVersion == slsa1.PredicateSLSAProvenance {
		slsaType = attestationv1.StatementTypeUri
	} else {
		slsaType = in_toto.StatementInTotoV01
	}

	digest := make(map[string]string)
	digest[slsa.Subject.Algorithm] = slsa.Subject.Digest
	subjectName := utils.ParseSubjectName(pkgPurl)

	data := map[string]interface{}{
		"type": slsaType,
		"subject": []map[string]interface{}{
			{
				"name":   subjectName,
				"uri":    pkgPurl,
				"digest": digest,
			},
		},
		"predicateType": slsa.Slsa.SlsaVersion,
		"predicate":     resultPred["slsa"],
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Replace "true" and "false" strings to boolean
	jsonData = bytes.ReplaceAll(jsonData, []byte(`"true"`), []byte(`true`))
	jsonData = bytes.ReplaceAll(jsonData, []byte(`"false"`), []byte(`false`))

	if err := protojson.Unmarshal(jsonData, s); err != nil {
		return nil, err
	}

	return s, nil
}

func ParseMap(input map[string]interface{}) map[string]interface{} {
	output := make(map[string]interface{})
	for key, value := range input {
		switch value := value.(type) {
		case map[string]interface{}:
			if _, ok := value["0"]; ok {
				output[key] = convertSlice(value)
				return output
			}
			output[key] = ParseMap(value)
		default:
			output[key] = value
		}
	}
	return output
}

func convertSlice(value map[string]interface{}) []interface{} {
	val := make([]interface{}, 0)
	for _, v := range value {
		val = append(val, v)
	}
	return val
}
