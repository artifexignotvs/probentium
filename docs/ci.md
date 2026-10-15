# Continuous integration

The `CI` workflow runs on pushes to `main`, pull requests and manual dispatch.
Its three jobs cover Linux with Python 3.11 and 3.13, plus macOS with Python 3.13.
The runner labels follow the current hosted images; their actual versions appear
in each workflow run. A configured platform is not a tested platform until its
job succeeds.

Each job builds the wheel and source distribution with normalized archive
metadata. It then installs each distribution in a separate fresh virtual
environment outside the checkout. Source-distribution installation uses explicit
build dependencies; installation of both local artifacts disables index access
and automatic runtime dependency installation.

The tests are copied into the external working directory. The workflow checks
that the imported module comes from the new virtual environment, runs the full
unit suite there, invokes the installed command, generates both synthetic demo
cases, verifies evidence, replays a case and compares its analysis with the
original. CLI subprocesses inherit that external working directory and the
installed interpreter. This catches packages that work only because their source
checkout happens to be importable.

## Permissions and dependencies

The workflow requests only read access to repository contents. Checkout does not
persist credentials. It uses no repository secrets and contains no release,
upload or publication step. Package-manager network access is needed for Python
and build-tool setup. The application checks use synthetic local evidence and
do not need external services.

Action revisions are pinned to full commit identifiers, verified against their
official upstream release tags:

- [Checkout v6.1.0](https://github.com/actions/checkout/tree/d23441a48e516b6c34aea4fa41551a30e30af803)
- [Setup Python v6.3.0](https://github.com/actions/setup-python/tree/ece7cb06caefa5fff74198d8649806c4678c61a1)

Build tools are pinned in the workflow. Updating their versions or action
revisions requires reviewing the upstream change and rerunning these checks.
An older run validates its recorded revision, not subsequent source changes.

CI is regression evidence. It does not establish forensic certification,
completeness of an investigation, absence of all defects or approval to publish
sensitive evidence.
