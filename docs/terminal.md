# Native terminal operation

PROBENTIUM runs locally without a browser, account, desktop or web service.
The optional development browser is a separate synthetic preview. It is not
required by the installed command.

## Start

```sh
probentium
probentium console --ascii
probentium console --no-banner
probentium console --case exercise/case
```

With no arguments and an interactive input and output, the command opens a
monochrome console with an original `[?]` text mark and the project motto,
*Ex indiciis, non ex fama.* Startup creates no case and acquires no evidence.
`--no-banner` hides the mark; `--ascii` escapes non-ASCII case text.

## Console commands

| Command | Effect |
| --- | --- |
| `open PATH` | Read an existing case and open its keyboard-driven workbench. |
| `create PATH` | Ask for a case name and create a private case at a new path. |
| `demo PATH` | Create a clearly synthetic investigation in a new directory. |
| `run COMMAND ...` | Execute a complete installed command with its usual validation. |
| `help` | Show the console command reference. |
| `quit` | Leave the console; `q` and `exit` also work. |

Existing destinations are not overwritten. Quote paths containing spaces.
`run` does not select a case implicitly: include `--case` for each command
that requires one. Shell commands, shell expansion, pipes and nested consoles
are not supported.

```text
probentium> demo exercise
probentium> open exercise/case
probentium> run status --case exercise/case
probentium> run verify --case exercise/case
probentium> run --help
probentium> quit
```

The case view uses `1`–`7` for the investigation views and `8`, `9`, `0` for
claims, scenarios and review. `:scope`, `:export` and `:retention` open the
remaining views. Press `?` for the current key reference and `q` to return
to the console. For `TERM=dumb`, `open` reports case counts without entering
the full-screen view. Narrow full-screen views show minimum-size guidance.
Those counts do not substitute for integrity verification.

EOF leaves the console successfully. Ctrl-C at the prompt or in the case view
exits with status 130. During a delegated `run` command, its interruption returns
command status 130 to the console. If a write was interrupted, inspect the case
and its committed checkpoints before retrying. Input lines are limited to 4,096
characters including the newline; oversized input is refused.

## Direct commands and automation

Every operation remains available without entering the console. The installed
help and [complete action reference](cli-reference.md) describe parameters,
side effects, output sensitivity and exit codes for all 97 actions.

```sh
probentium formats
probentium ingest --case CASE auth.log --format auth --label Authentication
probentium --format json verify --case CASE
```

Check `probentium formats` before selecting a source format. Direct commands
retain their machine-readable JSON output. Explicit `--format json` selects
the versioned result envelope. Interactive commands reject that mode before
printing a logo or opening a case. An empty non-interactive invocation returns
an argument error rather than waiting for input.

Use a normal user account. Root privileges and network access are not needed
for ordinary analysis of evidence you can already read. A Linux environment is
required for the current parser resource isolation and atomic restore behavior.
Optional encrypted packet transport invokes a separately installed `age`.
The case database itself remains plaintext.
