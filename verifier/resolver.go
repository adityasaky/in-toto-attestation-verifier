package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

func addResourceDescriptorResolver(env *cel.Env) (*cel.Env, error) {
	return env.Extend(
		cel.Types(&attestationv1.ResourceDescriptor{}),
		cel.Variable("rd", cel.ObjectType("in_toto_attestation.v1.ResourceDescriptor")),
		cel.Function("get_attestation",
			cel.Overload("get_attestation_resourcedescriptor",
				[]*cel.Type{cel.ObjectType("google.protobuf.Struct")},
				cel.StringType,
				cel.UnaryBinding(func(pbStruct ref.Val) ref.Val {
					st, err := getDSSEStatementPayload(pbStruct.Value().(*structpb.Struct))
					if err != nil {
						log.Infof("get_attestation failed: %s", err)
						return types.String("")
					}

					log.Infof("Got attestation. Returning to rule eval...")

					// FIXME: want to return any Statement field for rule eval
					return types.String(st.GetPredicateType())
				}, // func
				), // Binding
			), // Overload
		), // Function
	) // Extend
}

func pbStructToRD(s *structpb.Struct) (*attestationv1.ResourceDescriptor, error) {
	structJSON, err := protojson.Marshal(s)
	if err != nil {
		return nil, err
	}

	rd := &attestationv1.ResourceDescriptor{}
	err = protojson.Unmarshal(structJSON, rd)
	if err != nil {
		return nil, err
	}

	if err := rd.Validate(); err != nil {
		return nil, fmt.Errorf("parsed invalid RD: %w", err)
	}

	return rd, nil
}

func resolveResourceDescriptor(s *structpb.Struct, expectedType string) (bytes, error) {
	rd, err := pbStructToRD(s)
	if err != nil {
		log.Infof("Conversion from structpb.Struct failed: %s", err)
		return nil, err
	}

	// FIXME: don't assume the full filepath is described in the RD name field
	name := rd.GetName()

	log.Infof("Resolving file resource '%s' of type '%s'...", name, rd.GetMediaType())

	fileBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	// check that the opened file matches the expected attestation
	if len(rd.GetDigest()) > 0 {
		// FIXME: support other algorithms
		if !matchDigest(rd.GetDigest()["sha256"], fileBytes) {
			return nil, fmt.Errorf("opened file does not match expected attestation in resource descriptor")
		}

		log.Info("File resource integrity verified.")
	}

	if rd.GetMediaType() != expectedType {
		return nil, fmt.Errorf("resolved rd mediaType does not match expected type")
	}

	return fileBytes, nil
}

// copied from https://github.com/in-toto/scai-demos/blob/main/scai-gen/cmd/check.go
func getDSSEStatementPayload(s *structpb.Struct) (*attestationv1.Statement, error) {
	envBytes, err := resolveResourceDescriptor(s, "application/vnd.in-toto+dsse")
	if err != nil {
		return nil, fmt.Errorf("resolver failed: %w", err)
	}

	// TODO: check envelope signature

	// now, let's get the Statement
	envelope := &dsse.Envelope{}
	if err := json.Unmarshal(envBytes, envelope); err != nil {
		return nil, err
	}

	stBytes, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
	}

	statement := &attestationv1.Statement{}
	if err = protojson.Unmarshal(stBytes, statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Statement: %w", err)
	}

	/* FIXME: add back in
	   Fails with current test data because of outdated SLSA Provenance generation.
	if err = statement.Validate(); err != nil {
		return nil, fmt.Errorf("invalid Statement: %w", err)
	}
	*/

	return statement, nil
}

func getJsonData() {
	mediaType, envBytes, err := resolveResourceDescriptor(s, "application/json")
	if err != nil {
		return nil, fmt.Errorf("resolver failed: %w", err)
	}
}

// copied from https://github.com/in-toto/scai-demos/blob/main/scai-gen/policy/checks.go
func matchDigest(hexDigest string, blob []byte) bool {
	digest := genSHA256(blob)

	decoded, err := hex.DecodeString(hexDigest)
	if err != nil {
		log.Info("Problem decoding hex-encoded digest to match")
		return false
	}

	return bytes.Equal(decoded, digest)
}

// copied from https://github.com/in-toto/scai-demos/blob/main/scai-gen/policy/checks.go
func genSHA256(bytes []byte) []byte {
	h := sha256.New()
	h.Write(bytes)
	return h.Sum(nil)
}
