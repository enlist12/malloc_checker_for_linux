#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC_DIR="${ROOT_DIR}/src"
BUILD_DIR="${ROOT_DIR}/build"

LLVM_CONFIG=${LLVM_CONFIG:-}
if [[ -z "${LLVM_CONFIG}" ]]; then
  if command -v llvm-config-15 >/dev/null 2>&1; then
    LLVM_CONFIG=$(command -v llvm-config-15)
  elif command -v llvm-config >/dev/null 2>&1; then
    LLVM_CONFIG=$(command -v llvm-config)
  else
    LLVM_CONFIG=/mnt/data/capa_fuzz/llvm-project/build/bin/llvm-config
  fi
fi

mkdir -p "${BUILD_DIR}"

clang++-15 \
  "${SRC_DIR}/MallocCheckerAnalyzerMain.cpp" \
  "${SRC_DIR}/MallocCheckerAnalyzerOptions.cpp" \
  "${SRC_DIR}/MallocCheckerAnalyzerCore.cpp" \
  "${SRC_DIR}/IndirectCallResolver.cpp" \
  -std=c++17 \
  -O2 \
  -g \
  -o "${BUILD_DIR}/null-ptr-checker" \
  $("$LLVM_CONFIG" --cxxflags --ldflags --libs core irreader support analysis)
