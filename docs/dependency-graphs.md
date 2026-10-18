# Case dependency graphs

A graph freezes the explicitly declared links in one verified local case revision. It connects artifact bytes, records, parser versions and outputs with claims, evaluations, reviews, governance records, reporting tracks, filing snapshots, deadline rules/calendars and retention records. It does not discover unstated dependencies or certify the truth of an incident or legal conclusion.

```sh
probentium graph build --case CASE
probentium graph build --case CASE --input roots.json --expect-revision REVISION
probentium graph impact --case CASE --id GRAPH_ID --input changed-ids.json
```

Replace `CASE`, `REVISION` and `GRAPH_ID` with your existing case path, observed integer revision and the returned graph object's `id`. The default CLI result is the stored object wrapper. When using the optional versioned CLI envelope, read that wrapper from `data`. `graph impact` is read-only; it returns an impact report.

Omit `--input` to build the whole-case graph. A selected-root document has only these optional fields, with at least one existing identifier:

```json
{"artifact_ids":["ARTIFACT_ID"],"object_ids":["OBJECT_ID"]}
```

Each placeholder must be replaced by a real 64-character lowercase hexadecimal identity. Selected roots include explicit dependent objects and their declared prerequisites; referenced artifacts bring their acquired record/event lineage. Roots are not a request to invent a relationship. References outside the resolved scope remain visible as gaps.

For an impact report, use exactly:

```json
{"changed_ids":["EXISTING_REFERENCE_OR_GRAPH_NODE_ID"]}
```

An empty array is allowed to compare all changes since the saved graph. The report includes both requested changes and all observed structural changes. References may identify a stored artifact/object/event/record/run, or a typed node from a loaded graph. Unknown identifiers are rejected.

## Reading the result

Edges point from a dependency to its dependent. Nodes contain typed identities and content digests, not copied source text. Digests from free-form fields are never guessed to be links. Versioned legal-pack members and semantic evaluation bindings have separate nodes. `scoped_premise_candidate` marks a conservative candidate for review; it does not claim that the premise changed the verdict.

Explicit `supersedes` chains have revision-context nodes. A new awareness or population declaration therefore reaches the existing objects that refer to the earlier version. Legal-pack review and activation records have a separate context node, including an explicitly replaced previous pack. These are revision-based review candidates, not a date-sensitive finding that a particular rule is legally effective.

`complete_explicit_schema_references` means the recognized schemas' explicit references were represented in the selected scope. It does not mean all real-world dependencies are known. Unknown object schemas, unavailable references, opaque or incomplete parsing, authorized missing source bytes and declared unknown service dependencies make the graph `incomplete`, with typed `gaps`.

Evaluation-currentness nodes use the same selective dependency check as `claim stale`. A graph impact is a structural review aid: it does not replace that semantic check, invalidate a signature, approve a filing or rewrite a historical evaluation. Historical replay inputs and currentness assessments use different edge types. Whole-case historical replay-catalog links remain visible for provenance but do not propagate a current review-impact path; scoped claim and semantic-currentness links do.

## Storage and integrity

`graph build` verifies the case before reading its snapshot and binds `snapshot_revision` to that read. An expected revision conflict refuses the operation. The result is stored as immutable `unified_graph_chunk` objects plus a final `unified_graph` manifest. The manifest records counts, chunk IDs and a canonical structure digest. Graph receipts and validated synthetic exercise markers are excluded from graph dependencies, so creating a graph or updating its exercise marker does not itself change the structure digest.

Each chunk write increments the case revision. An interrupted build can leave unreferenced chunks; it cannot create a completed manifest before all its chunks exist. Retrying appends a new manifest without changing earlier history. This is not a single database transaction spanning the entire graph.

The Python `load_case_graph(case, graph_id)` helper validates and assembles the stored structure. `validate_snapshot_graphs(snapshot)` checks manifest/chunk references, counts, revision ordering and the aggregate digest during packet validation. These checks establish stored graph consistency, not independent semantic replay or authorship. `build_case_graph` and `impact` additionally require current case verification.

## Bounds

The graph hard limits are 250,000 nodes, 250,000 edges, 10,000,000 scanned rows per table and 64 MiB of canonical graph content. Whole-case lower-bound counts are checked before raw tables are materialized; construction checks exact counts as it proceeds. Selected graphs use the same hard limits. Large individual artifacts may exceed the edge limit even if an analysis of their events is allowed.

Chunks contain at most 2,048 nodes or edges. Existing case object-count and listing budgets still apply. There is no silently truncated successful graph. A limit returns exit 6; the final graph manifest is not written.

Impact reports retain the full bounded affected-node set and predecessor map. Human-readable `paths` contain at most 256 paths of at most 256 nodes each; `path_details_complete=false` explicitly marks an abbreviated path view. Missing or corrupt graph chunks fail verification. A malformed request uses exit 2, integrity failure 4, and revision conflict 5. Successful construction may still report `incomplete`: read the domain fields, not only exit 0.
