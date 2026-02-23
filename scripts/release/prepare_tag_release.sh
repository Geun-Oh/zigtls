#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: prepare_tag_release.sh --tag <tag> --repo <owner/repo> --out-dir <dir> [--ref <git-ref>] [--asset-name <name>] [--self-test]

Create release tarball + Zig package hash + build.zig.zon snippet + release notes metadata.
USAGE
}

self_test() {
  bash -n "$0"
  echo "self-test: ok"
}

TAG=""
REF=""
REPO=""
OUT_DIR=""
ASSET_NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --ref)
      REF="${2:-}"
      shift 2
      ;;
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --asset-name)
      ASSET_NAME="${2:-}"
      shift 2
      ;;
    --self-test)
      self_test
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$TAG" || -z "$REPO" || -z "$OUT_DIR" ]]; then
  echo "--tag, --repo, and --out-dir are required" >&2
  usage
  exit 2
fi

if [[ -z "$REF" ]]; then
  REF="refs/tags/$TAG"
fi
if [[ -z "$ASSET_NAME" ]]; then
  ASSET_NAME="zigtls-${TAG}.tar.gz"
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$OUT_DIR"

if ! git -C "$repo_root" rev-parse -q --verify "${REF}^{commit}" >/dev/null; then
  echo "git ref does not resolve to a commit: $REF" >&2
  exit 2
fi

tarball_path="$OUT_DIR/$ASSET_NAME"
prefix_dir="zigtls-${TAG}/"
git -C "$repo_root" archive --format=tar.gz --prefix="$prefix_dir" --output="$tarball_path" "${REF}^{commit}"

zig_cache_dir="$OUT_DIR/.zig-global-cache"
mkdir -p "$zig_cache_dir"
zig_hash="$(ZIG_GLOBAL_CACHE_DIR="$zig_cache_dir" zig fetch "$tarball_path" | tail -n 1)"
if [[ -z "$zig_hash" ]]; then
  echo "failed to compute Zig package hash" >&2
  exit 2
fi

package_url="https://github.com/${REPO}/releases/download/${TAG}/${ASSET_NAME}"
snippet_path="$OUT_DIR/build.zig.zon.snippet"
release_notes_path="$OUT_DIR/release-notes.md"
metadata_path="$OUT_DIR/metadata.env"

cat > "$snippet_path" <<EOF_SNIPPET
.dependencies = .{
    .zigtls = .{
        .url = "${package_url}",
        .hash = "${zig_hash}",
    },
},
EOF_SNIPPET

cat > "$release_notes_path" <<EOF_NOTES
## Zig Package Snippet

Use this in your consumer project's \`build.zig.zon\`:

\`\`\`zig
$(cat "$snippet_path")
\`\`\`

## Notes
- Asset file: \`${ASSET_NAME}\`
- Tag: \`${TAG}\`
- Hash computed from the exact uploaded tarball content.
EOF_NOTES

{
  printf 'TAG=%q\n' "$TAG"
  printf 'REF=%q\n' "$REF"
  printf 'ASSET_NAME=%q\n' "$ASSET_NAME"
  printf 'TARBALL_PATH=%q\n' "$tarball_path"
  printf 'PACKAGE_URL=%q\n' "$package_url"
  printf 'ZIG_PACKAGE_HASH=%q\n' "$zig_hash"
  printf 'SNIPPET_PATH=%q\n' "$snippet_path"
  printf 'RELEASE_NOTES_PATH=%q\n' "$release_notes_path"
} > "$metadata_path"

echo "prepared tag release artifacts"
echo "tag=$TAG"
echo "tarball=$tarball_path"
echo "hash=$zig_hash"
echo "snippet=$snippet_path"
echo "notes=$release_notes_path"
echo "metadata=$metadata_path"
