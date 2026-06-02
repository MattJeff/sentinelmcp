# STIX 2.1 Schema Attribution

The JSON Schema files in this directory (`bundle.json`, `indicator.json`,
`observed-data.json`, `software.json`, `infrastructure.json`, `relationship.json`,
`common.json`) are **re-extracted, simplified subsets** of the official OASIS
CTI STIX 2.1 JSON Schemas published at:

  https://github.com/oasis-open/cti-stix2-json-schemas

Original schemas are Copyright (c) OASIS Open and released under the
**BSD 3-Clause License** (see upstream `LICENSE`):

```
Copyright (c) OASIS Open 2021. All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of OASIS Open nor the names of its contributors may be
   used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## What changed

The schemas in this folder differ from upstream in the following ways, in
order to make them self-contained for offline test validation:

- All cross-file `$ref`s (e.g. `../common/core.json`, `../common/timestamp.json`,
  `../common/external-reference.json`, `../common/kill-chain-phase.json`) have
  been inlined or removed.
- Vocabularies (open-vocab enums) are loosened to `"type": "string"`.
- Optional cyber-observable extension structures are not validated.
- The set of required fields matches the OASIS spec (STIX 2.1 § 4.x and § 7.x).
- `additionalProperties: true` everywhere so unmodelled standard fields
  (`created_by_ref`, `revoked`, `object_marking_refs`, `confidence`, etc.)
  do not cause spurious failures.

These schemas are sufficient to assert that bundles produced by
`sentinel-stix::export_bundle` are **well-formed STIX 2.1** at the level of
identifiers, spec version, timestamps and required fields. They are NOT a
substitute for a full validator (e.g. `stix2-validator`) and intentionally
do not validate STIX patterning syntax, open-vocab membership, or every
extension type.

Contact: this attribution applies only to schema files in
`sentinel/crates/sentinel-stix/tests/data/stix-2.1-schemas/`. All Rust
source code in the surrounding crate is licensed under the workspace
license (MIT) as declared in the parent `Cargo.toml`.
