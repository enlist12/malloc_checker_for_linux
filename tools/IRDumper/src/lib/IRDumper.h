//==============================================================================
// FILE:
//    GetPointsPass.h
//
// DESCRIPTION:
//    collect points
//
// License: MIT
//==============================================================================

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include <map>
#include <vector>
#include <string>
#include <assert.h>
#include <stdio.h>
#include <iostream>
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Bitcode/BitcodeWriter.h"

//------------------------------------------------------------------------------
// New PM interface
//------------------------------------------------------------------------------
struct WriteBcPass : public llvm::PassInfoMixin<WriteBcPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                              llvm::ModuleAnalysisManager &);
public:
  void runOnModule(llvm::Module &M);

private:
};
