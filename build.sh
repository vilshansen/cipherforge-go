#!/bin/bash
# 
# Script til at tvær-kompilere Go-programmet (cipherforge.go) til
# flere platforme: Linux (amd64) og Windows (amd64).
#

# Stop scriptet øjeblikkeligt, hvis en kommando fejler
set -e

# Navnet på kildekoden
SOURCE_FILE="cipherforge.go"

echo "Starter tvær-kompilering af ${SOURCE_FILE}..."
echo "------------------------------------------------------"

# --- 1. BYG TIL LINUX ---
TARGET_OS="linux"
TARGET_ARCH="amd64"
OUTPUT_NAME="cipherforge_${TARGET_OS}_${TARGET_ARCH}"

echo "Bygger: ${TARGET_OS}/${TARGET_ARCH} -> ${OUTPUT_NAME}"
GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -o bin/${OUTPUT_NAME} ${SOURCE_FILE}

# --- 2. BYG TIL WINDOWS ---
TARGET_OS="windows"
TARGET_ARCH="amd64"
# Windows-eksekverbare SKAL have .exe extension
OUTPUT_NAME="cipherforge_${TARGET_OS}_${TARGET_ARCH}.exe"

echo "Bygger: ${TARGET_OS}/${TARGET_ARCH} -> ${OUTPUT_NAME}"
GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -o bin/${OUTPUT_NAME} ${SOURCE_FILE}

echo "------------------------------------------------------"
echo "Kompilering fuldført!"
echo "Følgende filer er klar til distribution:"
ls -l bin/cipherforge_*
