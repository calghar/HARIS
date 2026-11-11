# CI integrations

Both integrations run `haris` with `--yes`. Set the authorisation input only for targets you may test.

## Report formats

`--formats` takes `json`, `markdown`, `html`, `sarif`, `csv` and `junit`, for example `--formats sarif,json`.

| Format | File | Content |
|---|---|---|
| `sarif` | `.sarif` | SARIF 2.1.0. Refuted and suppressed findings carry `suppressions`. `--baseline` adds `baselineState`. |
| `junit` | `.xml` | One testcase per finding. Active findings fail; refuted and suppressed findings are skipped. |
| `csv` | `.csv` | One row per finding with a `status` column. Cells starting with `=`, `+`, `-` or `@` get a leading `'`. |
| `json` | `.json` | Schema: `src/haris/resources/schema/report.schema.json`. |

Markdown and HTML reports escape all target-controlled text. Code blocks show `<` and `>` as `&lt;` and `&gt;` in the Markdown file.

## GitHub Action

```yaml
name: haris
on:
  schedule:
    - cron: "0 3 * * 1"
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: calghar/HARIS@<commit-sha>
        with:
          url: https://staging.example.com
          authorised: "true"
          fail-on: high
```

The action installs HARIS from its own checkout, so the pinned commit sets the scanner version. It uploads the SARIF report to code scanning and then fails the job with the HARIS exit code (`1` findings at `fail-on`, `2` incomplete scan, `3` usage error).

| Input | Default | Purpose |
|---|---|---|
| `url`, `authorised` | required | Target and authorisation. |
| `profile` | `quick` | Built-in checks only. Other profiles need their scanners installed on the runner. |
| `scanners` | empty | Overrides the profile. |
| `fail-on` | `high` | Severity threshold. |
| `baseline` | empty | Earlier JSON report. |
| `output-dir` | `haris-reports` | Report directory in the workspace. |
| `upload-sarif` | `true` | Needs `security-events: write`. |

## GitLab CI

`integrations/gitlab/templates/haris.yml` is a component-style template. Include it with inputs:

```yaml
include:
  - project: your-group/haris
    ref: <tag>
    file: integrations/gitlab/templates/haris.yml
    inputs:
      url: https://staging.example.com
      authorised: "true"
      install_spec: "git+https://github.com/calghar/HARIS.git@<tag>"
```

The `haris-scan` job stores SARIF, JSON and JUnit reports as artifacts and publishes the JUnit report to the pipeline. The job fails when a finding at `fail_on` (default `high`) remains. GitLab does not read SARIF itself; use the artifact with your own tooling.
