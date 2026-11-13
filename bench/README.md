# Benchmark targets

`compose.yaml` pins every external image by tag and digest. Registry per image, checked 2026-11-12:

| Service | Registry | Reason |
|---|---|---|
| `dvwa` | `ghcr.io/digininja/dvwa` | Upstream publishes there |
| `dvwa_db` | `ghcr.io/mariadb/mariadb` | Pushed by the CI of the official `MariaDB/mariadb-docker` repo; tag 10.11 is 10.11.19, same as Docker Hub |
| `juice_shop` | Docker Hub `bkimminich/juice-shop` | The upstream release workflow pushes only there |
| `webgoat` | Docker Hub `webgoat/webgoat` | The upstream release workflow logs in only to Docker Hub |

Re-check a service when its image is bumped: `docker buildx imagetools inspect <image>:<tag>`.

Fixture services (`spa_catchall`, `vuln_ai_app`, `callback`) are built from `bench/fixtures`. Under a `docker-container` buildx builder, `docker compose` loads them into the local store without extra flags.

## Running HARIS in the production image

Benchmark scans run in the `bench` image, never on the host: nmap, nikto and nuclei exist only there. The `bench` stage is the production image plus Wapiti and sslyze, each in its own hashed venv under `/opt/tools`. The default build has neither tool. Without them a Wapiti scan ends `failed`, which makes the session `incomplete`.

```
docker build --target bench --load -t haris-prod:bench .
docker run --rm -v haris-bench-home:/home/haris haris-prod:bench nuclei -ut -ud /home/haris/nuclei-templates
python bench/run.py --haris "uv run python bench/in_image.py --log-level DEBUG" ...
```

`bench/run.py` splits `--haris` with `shlex` and appends `--url`, `--profile` and the rest, so `--log-level DEBUG` reaches `haris` inside the container.

`in_image.py` runs one `haris` scan in a container, rewrites `127.0.0.1` and `localhost` to `host.containers.internal`, forwards `HARIS_AUTH_HEADER` and `LITELLM_API_KEY`, copies the report out and removes the container. The `haris-bench-home` volume keeps the nuclei templates between scans. When `nuclei -ut` hits the GitHub API rate limit, unpack the `nuclei-templates` release tarball from `github.com/projectdiscovery/nuclei-templates/archive/refs/tags/<tag>.tar.gz` into that directory. Reports name the target host `host.containers.internal`.

## Seeding the WebGoat crawl for Wapiti

Wapiti follows links only, so WebGoat lesson endpoints stay unreached. `bench/wapiti_seeds.yaml` lists the start paths per target; the product default is `seed_paths: []`. Until `bench/run.py` reads that file, write a config with the paths merged in and run only the WebGoat target:

```
python - <<'PY'
import yaml
from haris.config.loader import default_config_path

raw = yaml.safe_load(default_config_path().read_text())
seeds = yaml.safe_load(open("bench/wapiti_seeds.yaml"))["webgoat"]["wapiti"]
for scanner in raw["scanners"]:
    if scanner["name"] == "wapiti":
        scanner.setdefault("options", {}).update(seeds)
open("tmp/bench-webgoat-seeds.yaml", "w").write(yaml.safe_dump(raw))
PY
HARIS_CONFIG="$PWD/tmp/bench-webgoat-seeds.yaml" python bench/run.py --targets webgoat --haris "uv run python bench/in_image.py"
```
