#include "MallocCheckerAnalyzer.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"

using namespace llvm;

namespace mallocchecker {

cl::list<std::string> InputFilenames(
    cl::Positional, cl::ZeroOrMore, cl::desc("<input bitcode files>"));

cl::opt<std::string> BCListFilename(
    "bc-list", cl::desc("Read input bitcode paths from this file"),
    cl::init(""));

cl::opt<std::string> OutputFilename(
    "filename", cl::desc("Write analysis results to this file"),
    cl::init("-"));

cl::opt<bool> ShowProgress(
    "show-progress", cl::desc("Print analysis progress to stderr"),
    cl::init(true));

cl::opt<unsigned> ProgressInterval(
    "progress-interval",
    cl::desc("Print progress every N sources while analyzing"),
    cl::init(100));

cl::opt<unsigned> MaxCallDepth(
    "max-call-depth",
    cl::desc("Maximum interprocedural propagation depth per source"),
    cl::init(6));

cl::opt<unsigned> MaxVisitsPerSource(
    "max-visits-per-source",
    cl::desc("Maximum taint states explored per allocation source"),
    cl::init(20000));

static bool readPathListFile(const std::string &Path,
                             std::vector<std::string> &Out,
                             std::string &Error) {
  ErrorOr<std::unique_ptr<MemoryBuffer>> BufOrErr =
      MemoryBuffer::getFile(Path, /*IsText=*/true);
  if (!BufOrErr) {
    Error = "failed to read bc list file '" + Path + "'";
    return false;
  }

  line_iterator It(**BufOrErr, true), End;
  for (; It != End; ++It) {
    StringRef Line = It->trim();
    if (Line.empty() || Line.startswith("#"))
      continue;
    Out.push_back(Line.str());
  }
  return true;
}

std::vector<std::string> collectInputPaths(std::string &Error) {
  std::vector<std::string> Paths;
  Paths.reserve(InputFilenames.size());

  for (const std::string &Path : InputFilenames)
    Paths.push_back(Path);

  if (!BCListFilename.empty()) {
    if (!readPathListFile(BCListFilename, Paths, Error))
      return {};
  } else if (Paths.size() == 1 &&
             sys::path::extension(Paths.front()).equals_insensitive(".list")) {
    std::vector<std::string> Expanded;
    if (!readPathListFile(Paths.front(), Expanded, Error))
      return {};
    Paths.swap(Expanded);
  }

  if (Paths.empty())
    Error = "no input bitcode files provided";

  return Paths;
}

std::unique_ptr<raw_ostream> createOutputStream(std::string &Error) {
  std::error_code EC;
  std::unique_ptr<raw_ostream> OS;
  if (OutputFilename == "-" || OutputFilename.empty()) {
    OS = std::make_unique<raw_fd_ostream>(1, false);
  } else {
    OS = std::make_unique<raw_fd_ostream>(OutputFilename, EC, sys::fs::OF_Text);
    if (EC) {
      Error = "failed to open output file '" + OutputFilename + "': " +
              EC.message();
      return nullptr;
    }
  }
  return OS;
}

void logPhase(const std::string &Message) {
  if (ShowProgress)
    errs() << "[malloc-checker] " << Message << "\n";
}

void logProgress(const std::string &Phase, size_t Current, size_t Total) {
  if (!ShowProgress || ProgressInterval == 0)
    return;
  if (Current != Total && (Current % ProgressInterval) != 0)
    return;
  errs() << "[malloc-checker] " << Phase << " " << Current << "/" << Total
         << "\n";
}

} // namespace mallocchecker
