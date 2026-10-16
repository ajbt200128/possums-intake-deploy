// Explicit syntax qualification only: no images, measurement, secrets or workload execution.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	config "github.com/tinfoilsh/tinfoil-config"
)

func qualify() (failure string) {
	failure = "VENDOR_DECODER_CAUSE_UNKNOWN"
	defer func() {
		if recover() != nil {
			failure = "VENDOR_DECODER_CAUSE_UNKNOWN"
		}
	}()
	if len(os.Args) != 3 || (os.Args[1] != "accept" && os.Args[1] != "reject") {
		return "VENDOR_DECODER_INPUT_INVALID"
	}
	for _, phase := range []string{"synthetic", "persistent-bootstrap", "persistent-serve", "persistent-diagnostic-serve"} {
		raw, err := os.ReadFile(filepath.Join(os.Args[2], "templates", phase+"-config.yml.in"))
		if err != nil || len(raw) > config.MaxConfigBytes {
			return "VENDOR_DECODER_FIXTURE_UNAVAILABLE"
		}
		if bytes.Count(raw, []byte("@CVM_PIN@")) != 1 || bytes.Count(raw, []byte("@IMAGE_DIGEST@")) != 1 {
			return "VENDOR_DECODER_FIXTURE_INVALID"
		}
		raw = bytes.ReplaceAll(raw, []byte("@CVM_PIN@"), []byte("0.14.14"))
		raw = bytes.ReplaceAll(raw, []byte("@IMAGE_DIGEST@"), []byte("sha256:"+strings.Repeat("b", 64)))
		options := config.Options{Mode: config.WorkloadMode}
		if phase == "synthetic" {
			if _, err := config.Decode(raw, options); err != nil {
				return "VENDOR_DECODER_BASELINE_REFUSED"
			}
			continue
		}
		binding := []byte("    persistent_volumes: ['ledger:/state']\n")
		if bytes.Count(raw, binding) != 1 {
			return "VENDOR_DECODER_FIXTURE_INVALID"
		}
		// A positive control isolates the binding field from the rest of the YAML.
		if _, err := config.Decode(bytes.Replace(raw, binding, nil, 1), options); err != nil {
			return "VENDOR_DECODER_CONTROL_REFUSED"
		}
		parsed, err := config.Decode(raw, options)
		if os.Args[1] == "reject" {
			if err == nil {
				return "VENDOR_DECODER_EXPECTED_REFUSAL_MISSING"
			}
			continue
		}
		if err != nil {
			return "VENDOR_DECODER_PERSISTENT_REFUSED"
		}
		if len(parsed.Volumes) != 1 || len(parsed.Containers) != 1 || parsed.Volumes[0].Name != "ledger" || parsed.Volumes[0].KeySecret != "" {
			return "VENDOR_DECODER_CONTRACT_MISMATCH"
		}
		// The interface keeps this same probe compilable against the old integer-owner API.
		owner, ok := any(&parsed.Volumes[0]).(interface{ OwnerIDs() (int, int, error) })
		if !ok {
			return "VENDOR_DECODER_OWNER_UNAVAILABLE"
		}
		uid, gid, err := owner.OwnerIDs()
		if err != nil || uid != 65532 || gid != 65532 {
			return "VENDOR_DECODER_OWNER_MISMATCH"
		}
		encoded, err := json.Marshal(parsed.Containers[0])
		if err != nil {
			return "VENDOR_DECODER_CONTRACT_UNAVAILABLE"
		}
		var fields struct{ PersistentVolumes []string }
		if json.Unmarshal(encoded, &fields) != nil || len(fields.PersistentVolumes) != 1 || fields.PersistentVolumes[0] != "ledger:/state" {
			return "VENDOR_DECODER_BINDING_MISMATCH"
		}
		for _, changed := range [][]byte{
			bytes.Replace(raw, []byte("persistent_volumes:"), []byte("volumes:"), 1),
			bytes.Replace(raw, []byte("persistent_volumes:"), []byte("unknown_fixture_field:"), 1),
			bytes.Replace(raw, []byte("owner: 65532"), []byte("owner: invalid_fixture_owner"), 1),
		} {
			if _, err := config.Decode(changed, options); err == nil {
				return "VENDOR_DECODER_NEGATIVE_ACCEPTED"
			}
		}
	}
	return ""
}

func main() {
	if failure := qualify(); failure != "" {
		fmt.Printf("{\"stage\":\"vendor_config_decoder\",\"code\":%q,\"constraint\":\"pinned_decoder_fixture_contract\",\"cause\":\"unknown_or_unconfirmed\",\"outcome\":\"no_effect\",\"next_step\":\"Keep release admission blocked; inspect the pinned decoder fixture and toolchain privately. Do not run measurement or retry publication.\"}\n", failure)
		os.Exit(1)
	}
	fmt.Println(`{"stage":"vendor_config_decoder","passed":true,"measurement":false,"runtime_verified":false}`)
}
