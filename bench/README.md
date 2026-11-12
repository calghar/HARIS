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
