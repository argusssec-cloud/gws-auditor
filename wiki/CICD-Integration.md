# CI/CD Integration

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (or only non-critical failures) |
| 1 | Non-critical failures exist |
| 2 | Critical failures exist (with `--fail-on-critical`) |

## Pipeline Example

```bash
gws-auditor --fail-on-critical --config config.yaml -f json -q
```

The `-q` flag suppresses output except errors, and `-f json` generates a machine-readable report.

## GitHub Actions

```yaml
- name: Run GWS Security Audit
  run: |
    gws-auditor --fail-on-critical --config config.yaml -f json -q
  env:
    GOOGLE_APPLICATION_CREDENTIALS: ${{ secrets.GWS_SA_KEY_PATH }}
```

## Using Standalone Executable

For pipelines without Python:

```yaml
- name: Download gws-auditor
  run: |
    curl -L -o gws-auditor https://github.com/your-org/argussec/releases/latest/download/gws-auditor-linux-amd64
    chmod +x gws-auditor

- name: Run audit
  run: ./gws-auditor --fail-on-critical -f json -q
```

## Report Artifacts

Upload the JSON report as a pipeline artifact for historical tracking:

```yaml
- uses: actions/upload-artifact@v4
  with:
    name: gws-audit-report
    path: reports/*.json
```
