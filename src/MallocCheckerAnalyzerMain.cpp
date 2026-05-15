#include "MallocCheckerAnalyzer.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/InitLLVM.h"

using namespace llvm;

int main(int argc, char **argv) {
  InitLLVM X(argc, argv);
  cl::ParseCommandLineOptions(
      argc, argv, "null-ptr-checker: detect unchecked nullable pointer uses\n");

  std::string Error;
  std::vector<std::string> Paths = mallocchecker::collectInputPaths(Error);
  if (!Error.empty()) {
    errs() << Error << "\n";
    return 1;
  }

  mallocchecker::AnalysisState State;

  mallocchecker::logPhase("phase 1/4 loading modules");
  if (!mallocchecker::loadModules(Paths, State, Error)) {
    errs() << Error << "\n";
    return 1;
  }

  mallocchecker::logPhase("phase 2/5 building direct-call index");
  mallocchecker::buildCallers(State);

  mallocchecker::logPhase("phase 3/6 collecting panic slab caches");
  mallocchecker::collectPanicSlabCaches(State);
  mallocchecker::logPhase("found " +
                          std::to_string(State.PanicSlabCaches.size()) +
                          " panic slab caches");

  mallocchecker::logPhase("phase 4/6 computing may-return-null functions");
  mallocchecker::computeMayReturnNullFunctions(State);
  mallocchecker::logPhase(
      "found " + std::to_string(State.MayReturnNullFunctions.size()) +
      " may-return-null functions");

  mallocchecker::logPhase("phase 5/6 collecting nullable-return sources");
  mallocchecker::collectSources(State);
  mallocchecker::logPhase("found " + std::to_string(State.Sources.size()) +
                          " nullable-return sources");

  mallocchecker::logPhase("phase 6/6 tracking unchecked dereferences");
  mallocchecker::analyzeSources(State);

  std::unique_ptr<raw_ostream> OS = mallocchecker::createOutputStream(Error);
  if (!OS) {
    errs() << Error << "\n";
    return 1;
  }

  mallocchecker::writeReports(State, *OS);
  OS->flush();
  mallocchecker::logPhase("report written");
  return 0;
}
