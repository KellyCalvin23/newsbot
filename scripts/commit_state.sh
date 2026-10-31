#!/usr/bin/env bash
# Commit state/ back to the repo. Does nothing if state did not change.
set -euo pipefail

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

git add state/
if git diff --cached --quiet; then
  echo "State unchanged; nothing to commit."
  exit 0
fi

git commit -m "chore(state): update bot state [skip ci]"

for attempt in 1 2 3; do
  if git pull --rebase origin "${GITHUB_REF_NAME:-main}" && git push origin "HEAD:${GITHUB_REF_NAME:-main}"; then
    echo "State pushed."
    exit 0
  fi
  echo "Push attempt ${attempt} failed; retrying."
  git rebase --abort 2>/dev/null || true
  sleep $((attempt * 5))
done

echo "Could not push state after 3 attempts." >&2
exit 1
