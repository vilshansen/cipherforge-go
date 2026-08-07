#!/usr/bin/env bash
set -euo pipefail

# Directly targeting the vilshansen repository
# Note: If the repo name doesn't have the -go suffix, change this to "vilshansen/cipherforge"
REPO="vilshansen/cipherforge-go" 
DEST_DIR="./cipherforge_releases"

echo "Downloading all versions from github.com/${REPO}..."
mkdir -p "${DEST_DIR}"

PAGE=1
while :; do
    API_URL="https://api.github.com/repos/${REPO}/releases?per_page=100&page=${PAGE}"
    echo "Fetching page ${PAGE} of releases..."
    
    # Fetch JSON data for the current page
    RELEASES_JSON=$(curl -sSL -H "Accept: application/vnd.github+json" "${API_URL}")
    
    # Catch API errors (e.g., rate limits or repository not found)
    if echo "${RELEASES_JSON}" | jq -e '.message' >/dev/null 2>&1; then
        echo "GitHub API Error: $(echo "${RELEASES_JSON}" | jq -r '.message')"
        exit 1
    fi

    RELEASE_COUNT=$(echo "${RELEASES_JSON}" | jq '. | length')
    
    # Stop if the page is empty
    if [ "${RELEASE_COUNT}" -eq 0 ]; then
        break
    fi

    # Parse and download each release on this page
    echo "${RELEASES_JSON}" | jq -c '.[]' | while read -r release; do
        TAG_NAME=$(echo "${release}" | jq -r '.tag_name')
        RELEASE_DIR="${DEST_DIR}/${TAG_NAME}"
        mkdir -p "${RELEASE_DIR}"
        
        echo " -> Downloading Version: ${TAG_NAME}"
        
        # 1. Download Compiled Assets (binaries)
        ASSET_URLS=$(echo "${release}" | jq -r '.assets[]?.browser_download_url')
        if [ -n "${ASSET_URLS}" ]; then
            while IFS= read -r url; do
                [ -z "${url}" ] && continue
                filename=$(basename "${url}")
                curl -sSL -o "${RELEASE_DIR}/${filename}" "${url}"
            done <<< "${ASSET_URLS}"
        fi
        
        # 2. Download Source Code (.zip)
        ZIP_URL=$(echo "${release}" | jq -r '.zipball_url')
        if [ "${ZIP_URL}" != "null" ] && [ -n "${ZIP_URL}" ]; then
             curl -sSL -o "${RELEASE_DIR}/source-${TAG_NAME}.zip" "${ZIP_URL}"
        fi
        
        # 3. Download Source Code (.tar.gz)
        TAR_URL=$(echo "${release}" | jq -r '.tarball_url')
        if [ "${TAR_URL}" != "null" ] && [ -n "${TAR_URL}" ]; then
             curl -sSL -o "${RELEASE_DIR}/source-${TAG_NAME}.tar.gz" "${TAR_URL}"
        fi
    done
    
    # If the page returned fewer than 100 items, we have reached the last page
    if [ "${RELEASE_COUNT}" -lt 100 ]; then
        break
    fi

    PAGE=$((PAGE + 1))
done

echo "Done! All versions successfully downloaded to ${DEST_DIR}/"

