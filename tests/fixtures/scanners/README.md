# Scanner golden fixtures

Raw output of the real tools, captured against `serve.py` on 127.0.0.1 (never any
other host). Parser tests read these files. Re-capture after a tool upgrade.

| Tool | Version | Fixtures | Status |
|------|---------|----------|--------|
| nuclei | v3.7.1 | `nuclei/phase1_tech.jsonl`, `phase2_scan.jsonl`, `auth_raw.jsonl`, `version.txt`, `templates-config.json` | real, paths anonymised |
| nikto | 2.6.0 (LW 2.5) | `nikto/http.json`, `nikto/https.json` | real |
| nmap | 7.99 | `nmap/scan.xml` | real, path anonymised |
| wapiti | 3.2.10 | `wapiti/all_modules.json`, `default_modules.json`, `auth_headers.json` | real; `all_modules.json` trimmed (vulnerable-software and anomaly lists) |
| sslyze | 6.3.0 | `sslyze/modern_tls.json`, `legacy_tls.json`, `no_connectivity.json` | real, lists trimmed to two entries, paths anonymised |

No fixture is synthetic.

## Notes

- Nuclei's official template repository is not installed. `nuclei/templates/` holds
  four locally authored templates (tech-detect, exposed-phpinfo, reflected-xss,
  http-missing-security-headers) used to produce the nuclei captures.
- `nuclei/auth_raw.jsonl` was captured without `-or` and with the secrets
  `nuclei-secret-token`, `nuclei-secret-key` and `nuclei-secret-cookie` in the
  `Authorization`, `X-API-Key` and `Cookie` headers.
- `wapiti/auth_headers.json` carries `wapiti-secret-token` and `wapiti-secret-key`.
- `sslyze/no_connectivity.json` is a scan of a closed port (`scan_result: null`).
- `version.txt` keeps nuclei's ANSI colour codes.

## Capture

```sh
python tests/fixtures/scanners/serve.py --port 18080
python tests/fixtures/scanners/serve.py --port 18443 --cert cert.pem --key key.pem
nikto -host http://127.0.0.1:18080 -Format json -output out -nointeractive -nocheck -Tuning 123b
nmap -oX scan.xml -p 18080,18443 -sV --open -- 127.0.0.1
wapiti -u http://127.0.0.1:18080/ -f json -o out.json -m common,-cookieflags,-csp,-http_headers,-https_redirect,-ssl --no-bugreport
sslyze --json_out out.json --quiet -- 127.0.0.1:18443
nuclei -u http://127.0.0.1:18080 -t tests/fixtures/scanners/nuclei/templates -jsonl -ot -or -duc
```
