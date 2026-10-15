# Contributing

Start with a reproducible observation. For a parser or rule change, provide a minimal synthetic fixture, the expected interpretation, the actual result and the exact command/version. Do not upload real evidence, credentials or personal case material to an issue.

Run `python -m unittest discover -s tests -v`, both `testifex demo` cases and any focused benchmark needed for the change. Tests should challenge the meaning of a finding and its uncertainty, not simply mirror the implementation. Describe any change to timestamp, provenance or source-accounting semantics explicitly.

New formats require documented source semantics, bounded handling of malformed data, original-record references and known-answer fixtures. Complex artifact formats should use maintained libraries with compatible licenses. A wrapper around an external tool must be identified as such.

Use clear English interfaces and documentation. Existing implementation comments include concise Latin; clarity around security-sensitive behavior takes priority. Keep dependencies and changes focused.

Contributions are submitted under Apache-2.0 unless explicitly agreed otherwise. Preserve required third-party notices. See SECURITY.md before reporting sensitive findings.
