#!/usr/bin/env bash
set -euo pipefail

REPO="vilshansen/cipherforge-go" 
DEST_DIR="./cipherforge_releases"

echo "Downloading releases from github.com/${REPO}..."
mkdir -p "${DEST_DIR}"

PAGE=1
while :; do
    API_URL="https://api.github.com/repos/${REPO}/releases?per_page=100&page=${PAGE}"
    echo "Fetching page ${PAGE} of releases..."
    
    RELEASES_JSON=$(curl -sSL -H "Accept: application/vnd.github+json" "${API_URL}")
    
    if echo "${RELEASES_JSON}" | jq -e '.message' >/dev/null 2>&1; then
        echo "GitHub API Error: $(echo "${RELEASES_JSON}" | jq -r '.message')"
        exit 1
    fi

    RELEASE_COUNT=$(echo "${RELEASES_JSON}" | jq '. | length')
    
    if [ "${RELEASE_COUNT}" -eq 0 ]; then
        break
    fi

    echo "${RELEASES_JSON}" | jq -c '.[]' | while read -r release; do
        TAG_NAME=$(echo "${release}" | jq -r '.tag_name')
        RELEASE_DIR="${DEST_DIR}/${TAG_NAME}"
        mkdir -p "${RELEASE_DIR}"
        
        echo "Processing Version: ${TAG_NAME}"
        
        # 1. Download Compiled Assets (binaries)
        ASSET_URLS=$(echo "${release}" | jq -r '.assets[]?.browser_download_url')
        if [ -n "${ASSET_URLS}" ]; then
            while IFS= read -r url; do
                [ -z "${url}" ] && continue
                filename=$(basename "${url}")
                target_file="${RELEASE_DIR}/${filename}"

                if [ -f "${target_file}" ]; then
                    echo "  [SKIPPED] ${filename} (already exists)"
                else
                    echo "  [DOWNLOADING] ${filename}"
                    curl -sSL -o "${target_file}" "${url}"
                fi
            done <<< "${ASSET_URLS}"
        fi
        
        # 2. Download Source Code (.zip)
        ZIP_URL=$(echo "${release}" | jq -r '.zipball_url')
        ZIP_FILE="${RELEASE_DIR}/source-${TAG_NAME}.zip"
        if [ "${ZIP_URL}" != "null" ] && [ -n "${ZIP_URL}" ]; then
            if [ -f "${ZIP_FILE}" ]; then
                echo "  [SKIPPED] source-${TAG_NAME}.zip (already exists)"
            else
                echo "  [DOWNLOADING] source-${TAG_NAME}.zip"
                curl -sSL -o "${ZIP_FILE}" "${ZIP_URL}"
            fi
        fi
        
        # 3. Download Source Code (.tar.gz)
        TAR_URL=$(echo "${release}" | jq -r '.tarball_url')
        TAR_FILE="${RELEASE_DIR}/source-${TAG_NAME}.tar.gz"
        if [ "${TAR_URL}" != "null" ] && [ -n "${TAR_URL}" ]; then
            if [ -f "${TAR_FILE}" ]; then
                echo "  [SKIPPED] source-${TAG_NAME}.tar.gz (already exists)"
            else
                echo "  [DOWNLOADING] source-${TAG_NAME}.tar.gz"
                curl -sSL -o "${TAR_FILE}" "${TAR_URL}"
            fi
        fi
    done
    
    if [ "${RELEASE_COUNT}" -lt 100 ]; then
        break
    fi

    PAGE=$((PAGE + 1))
done

echo "Done! Processing finished for ${DEST_DIR}/"
