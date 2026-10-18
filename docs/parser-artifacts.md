# Explicit parser distribution approval

A development checkout identifies selected parser source files. A selected-source
manifest is not an approved distribution and does not identify every installed
runtime dependency. Use the explicit distribution workflow when an investigation
requires the exact installed wheel and dependency bytes to be recorded.

Registration operates on an already installed, supported distribution. It does
not install packages, fetch a wheel, import code from a supplied archive or trust
an approval merely because it was included in an evidence packet. The operator
must supply and approve the exact product wheel and the supported pinned runtime
dependency wheels with their SHA-256 hashes. Editable installs are not eligible.

The registration document has exactly these fields:

```json
{
  "product_wheel": "wheelhouse/probentium-0.2.0.dev3-py3-none-any.whl",
  "product_sha256": "REPLACE_WITH_THE_ACTUAL_PRODUCT_SHA256",
  "dependency_wheels": [
    {"name": "rfc8785", "path": "REPLACE_WITH_WHEEL_PATH", "sha256": "REPLACE_WITH_ACTUAL_SHA256"},
    {"name": "cryptography", "path": "REPLACE_WITH_WHEEL_PATH", "sha256": "REPLACE_WITH_ACTUAL_SHA256"},
    {"name": "cffi", "path": "REPLACE_WITH_WHEEL_PATH", "sha256": "REPLACE_WITH_ACTUAL_SHA256"},
    {"name": "pycparser", "path": "REPLACE_WITH_WHEEL_PATH", "sha256": "REPLACE_WITH_ACTUAL_SHA256"}
  ],
  "approved_by": "ACTUAL_OPERATOR_REFERENCE",
  "reason": "ACTUAL_REVIEW_AND_APPROVAL_BASIS"
}
```

Placeholders deliberately are not valid hashes or actual approvals. Populate
these values from the distribution reviewed for this installation. The command
checks archive bounds, wheel metadata and RECORD, the exact dependency versions,
installed modules, native libraries and installed schemas. Unsupported platforms
or wheel tags fail explicitly. Interpreter/standard-library provenance, generated
console launchers and publisher identity are outside this manifest's attestation.

```sh
probentium parser-artifact register --case CASE --input parser-registration.json
probentium parser-artifact verify --case CASE --id PARSER_APPROVAL_ID
probentium ingest SOURCE.jsonl --case CASE --format events-v2 --label 'Copied source' --parser-artifact PARSER_APPROVAL_ID
probentium resume --case CASE --id PARSE_RUN_ID --parser-artifact PARSER_APPROVAL_ID
probentium replay --case CASE --parser-artifact PARSER_APPROVAL_ID
```

The returned immutable approval binds the operator statement and complete
manifest digest. The acquisition links that approval to a particular parse run.
A matching hash establishes byte equality, not the truth of the source, publisher
authenticity or an independent professional review.

For a packet replay, export the approved manifest JSON from the locally selected
approval's `data.manifest` and pass it explicitly:

```sh
probentium packet verify --input evidence.pbp --scope replay --parser-manifest selected-manifest.json
```

Reverification checks current installed bytes again. Merely restoring an approval
object does not select it for execution. If the exact parser is unavailable,
structural packet verification can still succeed while parser replay remains
unsupported. No executable parser supplied by a packet is run.

Installed bytecode caches are not part of the distribution identity. Parser and
analysis subprocesses use isolated interpreter startup, a fresh private bytecode
cache prefix and disabled cache writes, so unrelated installed caches are not
selected by those subprocesses. This is an import-integrity measure within the
trusted local operating-system model, not a hostile-code sandbox.
