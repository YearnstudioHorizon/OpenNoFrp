# Shared by the server installer and the HTTPS onboarding scripts.
RELEASE_REPO=YearnstudioHorizon/OpenNoFrp

release_curl() {
  curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 10 --max-time 180 "$@"
}

release_metadata() {
  local scratch="$1" api
  if ! command -v gh >/dev/null 2>&1; then
    echo "GitHub CLI with 'gh attestation verify' is required." >&2
    return 1
  fi
  api="$(release_curl --max-filesize 2097152 "https://api.github.com/repos/$RELEASE_REPO/releases/latest")" || return 1
  RELEASE_TAG="$(printf '%s\n' "$api" | awk -F'"' '/^[[:space:]]*"tag_name":/ { print $4; exit }')"
  if ! [[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Unable to select a stable OpenNoFrp release." >&2
    return 1
  fi
  RELEASE_DIR="$scratch"
  RELEASE_URL="https://github.com/$RELEASE_REPO/releases/download/$RELEASE_TAG"
  release_curl --max-filesize 1048576 "$RELEASE_URL/release-manifest.txt" -o "$scratch/release-manifest.txt" || return 1
  release_curl --max-filesize 1048576 "$RELEASE_URL/release-attestation.jsonl" -o "$scratch/release-attestation.jsonl" || return 1
  GH_PROMPT_DISABLED=1 gh attestation verify "$scratch/release-manifest.txt" \
    --hostname github.com --repo "$RELEASE_REPO" --bundle "$scratch/release-attestation.jsonl" \
    --signer-workflow "$RELEASE_REPO/.github/workflows/release.yml" \
    --source-ref "refs/tags/$RELEASE_TAG" --deny-self-hosted-runners
}

verify_release_asset() {
  local asset="$1" file="$2" metadata digest size actual
  metadata="$(awk -v name="$asset" 'NF == 3 && $3 == name { print $1, $2; n++ } END { if (n != 1) exit 1 }' "$RELEASE_DIR/release-manifest.txt")" || return 1
  read -r digest size <<< "$metadata"
  [[ "$digest" =~ ^[a-f0-9]{64}$ && "$size" =~ ^[1-9][0-9]{0,8}$ && "$size" -le 209715200 ]] || return 1
  [[ "$(wc -c < "$file" | tr -d '[:space:]')" == "$size" ]] || return 1
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum < "$file")" || return 1
  else
    actual="$(shasum -a 256 < "$file")" || return 1
  fi
  [[ "${actual%% *}" == "$digest" ]]
}

download_release_asset() {
  local asset="$1" dest="$2" url
  for url in "${3:-}" "$RELEASE_URL/$asset" "https://mirror.yearnstudio.cn/$RELEASE_URL/$asset"; do
    [ -n "$url" ] || continue
    if release_curl --max-filesize 209715200 "$url" -o "$dest" && verify_release_asset "$asset" "$dest"; then
      return 0
    fi
    rm -f -- "$dest"
  done
  echo "Unable to obtain a verified release asset: $asset" >&2
  return 1
}
