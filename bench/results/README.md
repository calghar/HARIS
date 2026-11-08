# Benchmark results

`bench/run.py` writes one folder per UTC date here: `<date>/<target>/raw/<label>/run<N>/` (HARIS output, stdout, stderr), `<date>/<target>/<label>/run<N>.json` (reports) and `<date>/<target>/runs/score/score.{json,md}`. Everything except this file is gitignored; the nightly workflow uploads the folder as the `bench-results` artifact.
