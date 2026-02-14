# Fuzz Regression Corpus

This directory stores regression inputs replayed by `scripts/fuzz/replay_corpus.sh`.

Layout convention:
- `record/`: inputs for record parser paths
- `handshake/`: inputs for handshake parser paths
- `session/`: inputs for session ingest paths

Keep historical crashers and minimized repro cases here.
