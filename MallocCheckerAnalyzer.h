#ifndef MALLOC_CHECKER_ANALYZER_H
#define MALLOC_CHECKER_ANALYZER_H

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace llvm {
class CallBase;
class Instruction;
class Value;
} // namespace llvm

namespace mallocchecker {

struct FunctionRecord {
  llvm::Function *F = nullptr;
  llvm::Module *M = nullptr;
  std::string ModulePath;
};

struct Source {
  const llvm::Instruction *AllocSite = nullptr;
  llvm::Function *AllocFunction = nullptr;
  std::string AllocKind;
};

struct Report {
  const Source *Src = nullptr;
  const llvm::Instruction *Sink = nullptr;
  llvm::Function *SinkFunction = nullptr;
  std::string SinkKind;
  llvm::SmallVector<std::string, 8> CallChain;
};

struct AnalysisState {
  std::vector<std::unique_ptr<llvm::LLVMContext>> Contexts;
  std::vector<std::unique_ptr<llvm::Module>> Modules;
  std::unordered_map<llvm::Function *, FunctionRecord> FunctionInfo;
  std::unordered_map<std::string, FunctionRecord> Definitions;
  std::unordered_map<llvm::Function *, llvm::SmallVector<llvm::CallBase *, 16>>
      Callers;
  std::vector<Source> Sources;
  std::vector<Report> Reports;
};

extern llvm::cl::list<std::string> InputFilenames;
extern llvm::cl::opt<std::string> BCListFilename;
extern llvm::cl::opt<std::string> OutputFilename;
extern llvm::cl::opt<bool> ShowProgress;
extern llvm::cl::opt<unsigned> ProgressInterval;
extern llvm::cl::opt<unsigned> MaxCallDepth;
extern llvm::cl::opt<unsigned> MaxVisitsPerSource;

std::vector<std::string> collectInputPaths(std::string &Error);
std::unique_ptr<llvm::raw_ostream> createOutputStream(std::string &Error);
void logPhase(const std::string &Message);
void logProgress(const std::string &Phase, size_t Current, size_t Total);

std::string formatDebugLoc(const llvm::Instruction *I);
std::string formatValue(const llvm::Value *V);

bool loadModules(const std::vector<std::string> &Paths, AnalysisState &State,
                 std::string &Error);
void buildCallers(AnalysisState &State);
void collectAllocationSources(AnalysisState &State);
void analyzeSources(AnalysisState &State);
void writeReports(const AnalysisState &State, llvm::raw_ostream &OS);

} // namespace mallocchecker

#endif
