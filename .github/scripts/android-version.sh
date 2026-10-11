#!/usr/bin/env bash
# Derive the app version from the git ref and publish it as step outputs.
#
#   refs/tags/turbo-v1.2.3  ->  versionName 1.2.3
#   anything else           ->  versionName 1.0.0-dev
#   versionCode             =   github.run_number
set -euo pipefail

ref="${GITHUB_REF:?GITHUB_REF is not set}"
version_code="${GITHUB_RUN_NUMBER:?GITHUB_RUN_NUMBER is not set}"

if [[ "$ref" == refs/tags/turbo-v* ]]; then
  version_name="${ref#refs/tags/turbo-v}"
  if [[ ! "$version_name" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "::error::Tag '${ref#refs/tags/}' must look like turbo-v<major>.<minor>.<patch>[-suffix]"
    exit 1
  fi
else
  version_name="1.0.0-dev"
fi

echo "versionName=${version_name} versionCode=${version_code}"
{
  echo "version_name=${version_name}"
  echo "version_code=${version_code}"
} >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
