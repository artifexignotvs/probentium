# Workflow research and scope decision

Primary documentation was reviewed on 2026-10-15. This was a bounded documentation review, not an audit of every implementation, a comparative benchmark or a user study.

| Existing project | Documented capability already present | Implication for this preview |
| --- | --- | --- |
| Plaso | Processing metadata, parser counters and source/time fields through its inspection and export tools. | Provenance and timestamp representation are established practice. Keep their context, do not claim to invent them. |
| Timesketch | Multiple timelines, annotations, analyzers and documented caveats around EVTX gaps. | Missing records and an absence of detected gaps both need careful interpretation. |
| Velociraptor | Reusable artifacts, notebooks, timelines, annotations and collection limits. | A frozen input plus query/configuration matters more for replay than a project or artifact name alone. |
| Dissect | Terminal queries across supported targets/plugins and typed forensic records. | Terminal-only forensics is not unique. This preview has much narrower parser coverage. |

Sources: [Plaso inspection](https://plaso.readthedocs.io/en/stable/sources/user/Using-pinfo.html), [Plaso time/output](https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html), [Timesketch concepts](https://timesketch.org/guides/user/basic-concepts/), [Velociraptor artifacts](https://docs.velociraptor.app/docs/artifacts/), [Velociraptor notebooks](https://docs.velociraptor.app/docs/notebooks/), [Velociraptor acquisition](https://docs.velociraptor.app/docs/file_collection/), [Dissect CLI](https://docs.dissect.tools/en/latest/tools/target-query.html), [Dissect records](https://docs.dissect.tools/en/latest/advanced/records.html).

The selected focus is a small offline terminal workflow that puts raw-record lineage, explicit clock assumptions, conservative coverage and replayable findings together. The three-minute demonstration shows a conclusion changing when clock uncertainty is supplied. It does not establish a feature absent from every other tool.

Unproven hypotheses: practitioners prefer this workflow for small cases; it reduces review time; maintained adapters/support have commercial demand. A useful next study asks several analysts to locate source bytes, explain the ambiguous ordering and reproduce findings without help, recording both time and errors.

## Name

TESTIFEX is a coined name from Latin roots associated with witness and maker. It is not presented as an attested classical Latin word. A bounded exact-name software/security search and direct PyPI, npm and crates.io checks found no obvious conflict at the time of review. This is not trademark clearance, a name reservation or a promise of continued package availability.
