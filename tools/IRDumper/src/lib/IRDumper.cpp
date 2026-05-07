#include "/usr/lib/llvm-15/include/llvm/IR/IRBuilder.h"
#include "/usr/lib/llvm-15/include/llvm/Passes/PassPlugin.h"
#include "/usr/lib/llvm-15/include/llvm/Passes/PassBuilder.h"
#include "IRDumper.h"
#include <set>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>

using namespace llvm;


void saveModule(Module &M, Twine filename)
{
	//int ll_fd;
	//sys::fs::openFileForWrite(filename + "_pt.ll", ll_fd, 
	//		sys::fs::F_RW | sys::fs::F_Text);
	//raw_fd_ostream ll_file(ll_fd, true, true);
	//M.print(ll_file, nullptr);

	int bc_fd;
	StringRef FN = filename.getSingleStringRef();
	sys::fs::openFileForWrite(
			FN.take_front(FN.size() - 2) + ".bc", bc_fd);
	raw_fd_ostream bc_file(bc_fd, true, true);
	WriteBitcodeToFile(M, bc_file);
}

void WriteBcPass::runOnModule(Module &M) {
	saveModule(M, M.getName());
}

PreservedAnalyses WriteBcPass::run(llvm::Module &M,
                                     llvm::ModuleAnalysisManager &)
{
	runOnModule(M);
    return PreservedAnalyses::all();
}

PassPluginLibraryInfo getPassPluginInfo()
{
  const auto callback = [](PassBuilder &PB)
  {
    PB.registerOptimizerLastEPCallback(
        [&](ModulePassManager &MPM, OptimizationLevel OL)
        {
          MPM.addPass(WriteBcPass());
        });
  };

  return {LLVM_PLUGIN_API_VERSION, "WriteBcPass", "0.0.1", callback};
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
  return getPassPluginInfo();
}