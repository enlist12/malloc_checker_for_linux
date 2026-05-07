#!/usr/bin/env bash
set -euo pipefail

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

clang++-15 \
  MallocCheckerAnalyzerMain.cpp \
  MallocCheckerAnalyzerOptions.cpp \
  MallocCheckerAnalyzerCore.cpp \
  -std=c++17 \
  -O2 \
  -g \
  -o malloc-checker-analyzer \
  $("$LLVM_CONFIG" --cxxflags --ldflags --libs core irreader support analysis)
