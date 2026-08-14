# PII masking (OpenMed) — integration triage

Goal: run the custom `pii-masking-openmed` policy (an OpenMed deidentification model
in the gateway's Python policy engine) in this OpenChoreo AI-gateway deployment, so
PHI is masked before OpenAI and restored on the response. Vendored from
`apim-ai-gateway-openmed-policy-use-cases/llm-proxy-pii-masking`.

## What is validated (live, on `feat/openchoreo-deployment`)

The policy ran end to end and masked email + phone before OpenAI, restoring them on
the response. The integration path that worked, without a full re-install:

1. Custom runtime image (torch + model + the policy baked in), built by the openmed
   repo's `ap gateway image build` → `pii-gateway-gateway-runtime:1.2.0-alpha2`.
2. Import it into k3d and point the `gateway-runtime` Deployment at it, adding
   `HF_HOME=/data/hf-cache`, an `hf-cache` volume, and ~6Gi/4cpu (the model loads in
   ~110s on first boot; the model downloads from HuggingFace, so pod DNS must work).
3. Give the **controller** the policy definition so it puts the policy in the chain:
   drop `policy/policy-definition.yaml` into the controller's `default-policies` dir
   (configmap + init-container merge). No controller image swap or DB wipe needed —
   the 1.1.0 controller already loads Python policy definitions (e.g. prompt-compressor).
4. Attach `pii-masking-openmed` (version v1) in the LlmProxy trait.

## Blocker

`pii-masking-openmed` does **not** coexist with `advanced-ratelimit` (the per-user
budget) in the same chain on the `1.2.0-alpha2` runtime:

```
[pol] Failed to build request-body payload  component=pythonbridge
      policy=pii-masking-openmed  error="convert shared context: convert shared
      metadata: proto: invalid type: []ratelimit.quotaResult"
```

The Go→Python bridge can't serialize `advanced-ratelimit`'s `quotaResult` metadata
when handing context to a Python policy. No policy ordering avoids it (request and
response phases sit on opposite sides of the budget policy). So today it is masking
XOR budget. The built-in Go `pii-masking-regex` has no bridge, so it works with the
budget — hence it ships on the main branch.

## Plan / next experiment

1. **Rebuild against stable `1.2.0`** (not `1.2.0-alpha2`) via `build.yaml`; the
   serialization bug is plausibly alpha-only. Import, swap the runtime image, re-test
   `advanced-ratelimit` + `pii-masking-openmed` together. Operator `0.11.0` ships
   runtime `1.2.0` if a matched operator is wanted, but the image-override test does
   not require the operator upgrade.
2. If stable 1.2.0 fixes it: make it reproducible — commit the runtime-image override,
   the controller default-policies injection, and the trait swap; document the custom
   image build (and where it is hosted, since it is ~2GB with torch).
3. If it does not: report upstream (pythonbridge should skip non-serializable internal
   metadata), and decide whether OpenMed masking replaces the budget or the budget stays.

## Open questions

- Where does the ~2GB custom runtime image live for reproducible deploys (registry)?
- Model download at boot needs egress to HuggingFace; acceptable, or pre-bake the model?
- Operator upgrade to 0.11.0/runtime 1.2.0 vs. image-override only.
