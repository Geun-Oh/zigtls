# Fuzz Regression Corpus

This directory stores regression inputs replayed by `scripts/fuzz/replay_corpus.sh`.

Layout convention:
- `record/`: inputs for record parser paths
- `handshake/`: inputs for handshake parser paths
- `session/`: inputs for session ingest paths

Keep historical crashers and minimized repro cases here.

Replay behavior:
- `scripts/fuzz/replay_corpus.sh` builds and invokes `zig-out/bin/corpus-replay`.
- Each corpus file is dispatched by top-level bucket (`record`, `handshake`, `session`) into the corresponding parser/session ingest path.

Current baseline seeds:
- `record/invalid-legacy-version.bin`: malformed record legacy version probe
- `handshake/truncated-serverhello.bin`: truncated handshake framing probe
- `session/downgrade-tls12-marker.bin`: ServerHello downgrade marker `DOWNGRD\x01`
- `session/downgrade-tls11-marker.bin`: ServerHello downgrade marker `DOWNGRD\x00`
