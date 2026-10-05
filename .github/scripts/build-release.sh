#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

version=$(python3 .github/scripts/release.py version)
required_go=$(awk '$1 == "go" {print $2}' go.mod)
export GOTOOLCHAIN=local
if [[ $(go env GOVERSION) != "go$required_go" ]]; then
  echo "Release builds require Go $required_go from go.mod" >&2
  exit 1
fi
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
revision=${GITHUB_SHA:-$(git rev-parse --verify HEAD 2>/dev/null || echo unknown)}
epoch=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD 2>/dev/null || echo 0)}
[[ "$revision" == unknown || "$revision" =~ ^[0-9a-f]{40}$ ]]
[[ "$epoch" =~ ^[0-9]+$ ]]
name="novakiosk-agent-$version-linux-x86_64"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
package="$staging/$name"
mkdir -p "$package/bin" "$package/licenses" dist

go mod download
go mod verify
go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$version" \
  -o "$package/bin/novakiosk-agent" ./cmd/novakiosk-agent
cp README.md LICENSE "$package/"
go_root=$(go env GOROOT)
websocket_root=$(go list -m -f '{{.Dir}}' github.com/gorilla/websocket)
cp "$go_root/LICENSE" "$package/licenses/Go-LICENSE"
cp "$go_root/PATENTS" "$package/licenses/Go-PATENTS"
cp "$websocket_root/LICENSE" "$package/licenses/Gorilla-WebSocket-LICENSE"
tpm_root=$(go list -m -f '{{.Dir}}' github.com/google/go-tpm)
sys_root=$(go list -m -f '{{.Dir}}' golang.org/x/sys)
cp "$tpm_root/LICENSE" "$package/licenses/Go-TPM-LICENSE"
cp "$sys_root/LICENSE" "$package/licenses/Go-x-sys-LICENSE"
cp "$sys_root/PATENTS" "$package/licenses/Go-x-sys-PATENTS"
{
  printf 'NOVA Kiosk Agent %s\nSource revision: %s\nSource epoch: %s\n' "$version" "$revision" "$epoch"
  printf 'Target: linux/amd64 (x86-64-v1), CGO_ENABLED=0\n'
  go version
  go version -m "$package/bin/novakiosk-agent" | sed "1s|^[^:]*:|bin/novakiosk-agent:|"
} > "$package/BUILD-INFO.txt"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --mode=u=rwX,go=rX \
  -C "$staging" -cf - "$name" | gzip -n > "dist/$name.tar.gz"
(cd dist && sha256sum "$name.tar.gz" > SHA256SUMS)
