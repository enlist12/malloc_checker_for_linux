#include "MallocCheckerAnalyzer.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Operator.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"

#include <algorithm>
#include <deque>
#include <set>
#include <tuple>

using namespace llvm;

namespace mallocchecker {

namespace {

struct StateKey {
  const Value *Tracked = nullptr;
  const Function *Context = nullptr;
  bool IsMemory = false;
  unsigned Depth = 0;

  bool operator==(const StateKey &Other) const {
    return std::tie(Tracked, Context, IsMemory, Depth) ==
           std::tie(Other.Tracked, Other.Context, Other.IsMemory, Other.Depth);
  }
};

struct StateKeyHash {
  size_t operator()(const StateKey &K) const {
    size_t H = reinterpret_cast<uintptr_t>(K.Tracked);
    H ^= reinterpret_cast<uintptr_t>(K.Context) + 0x9e3779b9 + (H << 6) + (H >> 2);
    H ^= static_cast<size_t>(K.IsMemory) + 0x9e3779b9 + (H << 6) + (H >> 2);
    H ^= static_cast<size_t>(K.Depth) + 0x9e3779b9 + (H << 6) + (H >> 2);
    return H;
  }
};

struct WorkItem {
  const Value *Tracked = nullptr;
  const Function *Context = nullptr;
  bool IsMemory = false;
  unsigned Depth = 0;
  SmallVector<std::string, 8> CallChain;
};

static const AllocaInst *asTrackedStackSlot(const Value *V) {
  return dyn_cast<AllocaInst>(V->stripPointerCasts());
}

struct ReportKey {
  const Instruction *SourceSite = nullptr;
  const Function *SourceFunction = nullptr;
  std::string SourceKind;

  bool operator==(const ReportKey &Other) const {
    return SourceSite == Other.SourceSite &&
           SourceFunction == Other.SourceFunction &&
           SourceKind == Other.SourceKind;
  }
};

struct ReportKeyHash {
  size_t operator()(const ReportKey &K) const {
    size_t H = reinterpret_cast<uintptr_t>(K.SourceSite);
    H ^= reinterpret_cast<uintptr_t>(K.SourceFunction) + 0x9e3779b9 + (H << 6) +
         (H >> 2);
    H ^= std::hash<std::string>{}(K.SourceKind) + 0x9e3779b9 + (H << 6) +
         (H >> 2);
    return H;
  }
};

struct ValuePairKey {
  const Value *A = nullptr;
  const Value *B = nullptr;

  bool operator==(const ValuePairKey &Other) const {
    return A == Other.A && B == Other.B;
  }
};

struct ValueAtKey {
  const Value *V = nullptr;
  const Instruction *At = nullptr;

  bool operator==(const ValueAtKey &Other) const {
    return V == Other.V && At == Other.At;
  }
};

struct ValueAtKeyHash {
  size_t operator()(const ValueAtKey &K) const {
    size_t H = reinterpret_cast<uintptr_t>(K.V);
    H ^= reinterpret_cast<uintptr_t>(K.At) + 0x9e3779b9 + (H << 6) + (H >> 2);
    return H;
  }
};

struct ValuePairKeyHash {
  size_t operator()(const ValuePairKey &K) const {
    size_t H = reinterpret_cast<uintptr_t>(K.A);
    H ^= reinterpret_cast<uintptr_t>(K.B) + 0x9e3779b9 + (H << 6) + (H >> 2);
    return H;
  }
};

static const Value *stripTrackedValue(const Value *V);

static bool isNullConstant(const Value *V) {
  if (!V)
    return false;
  V = V->stripPointerCasts();
  if (auto *CI = dyn_cast<ConstantInt>(V))
    return CI->isZero();
  return isa<ConstantPointerNull>(V);
}

static bool isNonnullPointerConstant(const Value *V) {
  if (!V)
    return false;
  if (!V->getType()->isPointerTy() || !isa<Constant>(V))
    return false;
  return !isNullConstant(V);
}

static bool hasNullComparisonInValueFlow(
    const Value *Root,
    const std::unordered_map<Function *, SmallVector<CallBase *, 16>> *Callers) {
  SmallVector<const Value *, 32> Worklist;
  SmallPtrSet<const Value *, 32> Seen;
  Worklist.push_back(Root);

  while (!Worklist.empty()) {
    const Value *V = stripTrackedValue(Worklist.pop_back_val());
    if (!Seen.insert(V).second)
      continue;

    for (const User *U : V->users()) {
      if (auto *Cmp = dyn_cast<ICmpInst>(U)) {
        if (!Cmp->isEquality())
          continue;
        if (isNullConstant(Cmp->getOperand(0)) ||
            isNullConstant(Cmp->getOperand(1)))
          return true;
        continue;
      }

      if (isa<BitCastInst>(U) || isa<AddrSpaceCastInst>(U) ||
          isa<GetElementPtrInst>(U) || isa<PHINode>(U) || isa<SelectInst>(U) ||
          isa<FreezeInst>(U)) {
        Worklist.push_back(cast<Value>(U));
        continue;
      }

      if (auto *SI = dyn_cast<StoreInst>(U)) {
        if (SI->getValueOperand() != V)
          continue;
        const Value *Ptr = SI->getPointerOperand()->stripPointerCasts();
        if (const AllocaInst *Slot = asTrackedStackSlot(Ptr))
          Worklist.push_back(Slot);
        else {
          for (const User *MemU : Ptr->users()) {
            auto *LI = dyn_cast<LoadInst>(MemU);
            if (!LI)
              continue;
            if (LI->getPointerOperand()->stripPointerCasts() != Ptr)
              continue;
            Worklist.push_back(LI);
          }
        }
        continue;
      }

      if (auto *LI = dyn_cast<LoadInst>(U)) {
        if (LI->getPointerOperand()->stripPointerCasts() ==
            V->stripPointerCasts()) {
          Worklist.push_back(LI);
        }
        continue;
      }

      if (auto *RI = dyn_cast<ReturnInst>(U)) {
        if (!Callers)
          continue;
        const Function *F = RI->getFunction();
        auto It = Callers->find(const_cast<Function *>(F));
        if (It == Callers->end())
          continue;
        for (CallBase *CallerCB : It->second)
          Worklist.push_back(CallerCB);
      }
    }
  }

  return false;
}

static const Value *stripTrackedValue(const Value *V) {
  if (!V)
    return nullptr;
  while (true) {
    if (auto *CE = dyn_cast<ConstantExpr>(V)) {
      if (CE->isCast() || CE->getOpcode() == Instruction::GetElementPtr) {
        V = CE->getOperand(0);
        continue;
      }
    }
    if (auto *I = dyn_cast<Instruction>(V)) {
      if (isa<BitCastInst>(I) || isa<AddrSpaceCastInst>(I) ||
          isa<FreezeInst>(I) || isa<GetElementPtrInst>(I)) {
        V = I->getOperand(0);
        continue;
      }
    }
    return V;
  }
}

static bool sameTrackedValueOneWay(
    const Value *A, const Value *B,
    std::unordered_set<ValuePairKey, ValuePairKeyHash> &VisitedPairs) {
  A = stripTrackedValue(A);
  B = stripTrackedValue(B);
  if (!A || !B)
    return false;
  if (A == B)
    return true;

  if (auto *LA = dyn_cast<LoadInst>(A)) {
    if (auto *LB = dyn_cast<LoadInst>(B)) {
      if (LA->getPointerOperand()->stripPointerCasts() ==
          LB->getPointerOperand()->stripPointerCasts())
        return true;
    }
  }
  if (!VisitedPairs.insert(ValuePairKey{A, B}).second)
    return false;

  if (auto *PN = dyn_cast<PHINode>(A)) {
    for (const Value *Incoming : PN->incoming_values()) {
      if (sameTrackedValueOneWay(Incoming, B, VisitedPairs))
        return true;
    }
    return false;
  }

  if (auto *SI = dyn_cast<SelectInst>(A))
    return sameTrackedValueOneWay(SI->getTrueValue(), B, VisitedPairs) ||
           sameTrackedValueOneWay(SI->getFalseValue(), B, VisitedPairs);

  if (auto *LI = dyn_cast<LoadInst>(A)) {
    const Value *Ptr = LI->getPointerOperand()->stripPointerCasts();
    if (auto *AI = dyn_cast<AllocaInst>(Ptr)) {
      for (const User *U : AI->users()) {
        if (auto *Store = dyn_cast<StoreInst>(U)) {
          if (Store->getPointerOperand()->stripPointerCasts() == AI &&
              sameTrackedValueOneWay(Store->getValueOperand(), B, VisitedPairs))
            return true;
        }
      }
    }
  }

  return false;
}

static bool sameTrackedValue(const Value *A, const Value *B) {
  if (!A || !B)
    return false;
  std::unordered_set<ValuePairKey, ValuePairKeyHash> VisitedAB;
  if (sameTrackedValueOneWay(A, B, VisitedAB))
    return true;
  std::unordered_set<ValuePairKey, ValuePairKeyHash> VisitedBA;
  return sameTrackedValueOneWay(B, A, VisitedBA);
}

static bool matchNonnullCompare(const Value *Cond, const Value *Target,
                                bool &TrueMeansNonnull) {
  if (!Cond || !Target)
    return false;
  Cond = Cond->stripPointerCasts();
  auto *Cmp = dyn_cast<ICmpInst>(Cond);
  if (!Cmp || !Cmp->isEquality())
    return false;

  const Value *L = stripTrackedValue(Cmp->getOperand(0));
  const Value *R = stripTrackedValue(Cmp->getOperand(1));
  if (isNullConstant(L) && sameTrackedValue(R, Target)) {
    TrueMeansNonnull = Cmp->getPredicate() == CmpInst::ICMP_NE;
    return true;
  }
  if (isNullConstant(R) && sameTrackedValue(L, Target)) {
    TrueMeansNonnull = Cmp->getPredicate() == CmpInst::ICMP_NE;
    return true;
  }
  return false;
}

static bool isDefinitelyNonnullValueAt(const Value *V, const Instruction *At,
                                       DominatorTree &DT);
static bool isDefinitelyNonnullValueAtImpl(
    const Value *V, const Instruction *At, DominatorTree &DT,
    std::unordered_set<ValueAtKey, ValueAtKeyHash> &Visited);

static const Value *stripIntegerCastValue(const Value *V) {
  if (!V)
    return nullptr;
  while (true) {
    V = V->stripPointerCasts();
    if (auto *CE = dyn_cast<ConstantExpr>(V)) {
      if (CE->isCast()) {
        V = CE->getOperand(0);
        continue;
      }
    }
    if (auto *I = dyn_cast<Instruction>(V)) {
      if (isa<PtrToIntInst>(I) || isa<IntToPtrInst>(I) || isa<ZExtInst>(I) ||
          isa<SExtInst>(I) || isa<TruncInst>(I)) {
        V = I->getOperand(0);
        continue;
      }
    }
    return V;
  }
}

static bool isErrThresholdConstant(const Value *V) {
  if (!V)
    return false;
  V = V->stripPointerCasts();
  const ConstantInt *CI = dyn_cast<ConstantInt>(V);
  if (!CI) {
    if (const auto *CE = dyn_cast<ConstantExpr>(V)) {
      if (CE->isCast())
        CI = dyn_cast<ConstantInt>(CE->getOperand(0));
    }
  }
  if (!CI)
    return false;
  APInt Val = CI->getValue();
  return Val.isNegative();
}

static bool matchErrPtrNonnullCompare(const Value *Cond, const Value *Target,
                                      bool &TrueMeansNonnull) {
  if (!Cond || !Target)
    return false;
  Cond = Cond->stripPointerCasts();
  auto *Cmp = dyn_cast<ICmpInst>(Cond);
  if (!Cmp)
    return false;

  const Value *L = stripIntegerCastValue(Cmp->getOperand(0));
  const Value *R = stripIntegerCastValue(Cmp->getOperand(1));

  if (sameTrackedValue(L, Target) && isErrThresholdConstant(Cmp->getOperand(1))) {
    switch (Cmp->getPredicate()) {
    case CmpInst::ICMP_UGE:
    case CmpInst::ICMP_UGT:
    case CmpInst::ICMP_SLT:
    case CmpInst::ICMP_SLE:
      TrueMeansNonnull = true;
      return true;
    default:
      return false;
    }
  }

  if (sameTrackedValue(R, Target) && isErrThresholdConstant(Cmp->getOperand(0))) {
    switch (Cmp->getPredicate()) {
    case CmpInst::ICMP_ULE:
    case CmpInst::ICMP_ULT:
    case CmpInst::ICMP_SGT:
    case CmpInst::ICMP_SGE:
      TrueMeansNonnull = true;
      return true;
    default:
      return false;
    }
  }

  return false;
}

static bool matchNonnullCondition(const Value *Cond, const Value *Target,
                                  bool &TrueMeansNonnull) {
  if (!Cond || !Target)
    return false;
  if (matchNonnullCompare(Cond, Target, TrueMeansNonnull))
    return true;
  if (matchErrPtrNonnullCompare(Cond, Target, TrueMeansNonnull))
    return true;

  Cond = Cond->stripPointerCasts();
  if (auto *Cmp = dyn_cast<ICmpInst>(Cond)) {
    if (Cmp->isEquality() && Cmp->getOperand(0)->getType()->isIntegerTy(1)) {
      const Value *Other = nullptr;
      bool Flip = false;
      if (const auto *C = dyn_cast<ConstantInt>(Cmp->getOperand(0))) {
        Other = Cmp->getOperand(1);
        Flip = C->isZero();
      } else if (const auto *C = dyn_cast<ConstantInt>(Cmp->getOperand(1))) {
        Other = Cmp->getOperand(0);
        Flip = C->isZero();
      }
      if (Other) {
        bool InnerTrueMeansNonnull = false;
        if (matchNonnullCondition(Other, Target, InnerTrueMeansNonnull)) {
          bool EqMeansInner = Cmp->getPredicate() == CmpInst::ICMP_EQ;
          TrueMeansNonnull =
              (EqMeansInner == !Flip) ? InnerTrueMeansNonnull
                                      : !InnerTrueMeansNonnull;
          return true;
        }
      }
    }
  }
  if (auto *I = dyn_cast<Instruction>(Cond)) {
    if (I->getOpcode() == Instruction::Xor && I->getType()->isIntegerTy(1)) {
      const Value *Other = nullptr;
      auto *C0 = dyn_cast<ConstantInt>(I->getOperand(0));
      auto *C1 = dyn_cast<ConstantInt>(I->getOperand(1));
      if (C0 && C0->isOne())
        Other = I->getOperand(1);
      else if (C1 && C1->isOne())
        Other = I->getOperand(0);
      if (Other) {
        bool InnerTrueMeansNonnull = false;
        if (matchNonnullCondition(Other, Target, InnerTrueMeansNonnull)) {
          TrueMeansNonnull = !InnerTrueMeansNonnull;
          return true;
        }
      }
    }
  }
  if (auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    bool LTrueMeansNonnull = false;
    bool RTrueMeansNonnull = false;
    if (BO->getOpcode() == Instruction::And &&
        matchNonnullCondition(BO->getOperand(0), Target, LTrueMeansNonnull) &&
        matchNonnullCondition(BO->getOperand(1), Target, RTrueMeansNonnull) &&
        LTrueMeansNonnull && RTrueMeansNonnull) {
      TrueMeansNonnull = true;
      return true;
    }
    if (BO->getOpcode() == Instruction::Or &&
        matchNonnullCondition(BO->getOperand(0), Target, LTrueMeansNonnull) &&
        matchNonnullCondition(BO->getOperand(1), Target, RTrueMeansNonnull) &&
        !LTrueMeansNonnull && !RTrueMeansNonnull) {
      TrueMeansNonnull = false;
      return true;
    }
  }

  return false;
}

static bool impliesNonnullOnEdge(const Value *Target, const BasicBlock *Pred,
                                 const BasicBlock *Succ) {
  if (!Target || !Pred || !Succ)
    return false;
  auto *BI = dyn_cast<BranchInst>(Pred->getTerminator());
  if (!BI || !BI->isConditional())
    return false;

  bool TrueMeansNonnull = false;
  if (!matchNonnullCondition(BI->getCondition(), Target, TrueMeansNonnull))
    return false;

  if (BI->getSuccessor(TrueMeansNonnull ? 0 : 1) == Succ)
    return true;
  return false;
}

static bool isNonnullAssume(const Instruction &I, const Value *Target) {
  if (!Target)
    return false;
  auto *CB = dyn_cast<CallBase>(&I);
  if (!CB || !CB->getCalledFunction())
    return false;
  if (CB->getCalledFunction()->getIntrinsicID() != Intrinsic::assume)
    return false;
  if (CB->arg_empty())
    return false;

  bool TrueMeansNonnull = false;
  return matchNonnullCondition(CB->getArgOperand(0), Target, TrueMeansNonnull) &&
         TrueMeansNonnull;
}

static bool isValueNonnullAtInstruction(const Value *Target,
                                        const Instruction *At,
                                        DominatorTree &DT) {
  if (!Target || !At)
    return false;
  const BasicBlock *BB = At->getParent();
  const Value *Base = stripTrackedValue(Target);
  if (!Base)
    return false;
  const DomTreeNode *BBNode = DT.getNode(BB);

  for (const BasicBlock &Candidate : *At->getFunction()) {
    auto *BI = dyn_cast<BranchInst>(Candidate.getTerminator());
    if (!BI || !BI->isConditional())
      continue;

    bool TrueMeansNonnull = false;
    if (!matchNonnullCondition(BI->getCondition(), Base, TrueMeansNonnull))
      continue;

    const BasicBlock *SafeSucc = BI->getSuccessor(TrueMeansNonnull ? 0 : 1);
    if (SafeSucc == BB)
      return true;
    if (!BBNode)
      continue;
    if (DT.getNode(SafeSucc) && DT.dominates(SafeSucc, BB))
      return true;
  }

  for (const Instruction &I : *BB) {
    if (&I == At)
      break;
    if (isNonnullAssume(I, Base))
      return true;
  }

  if (!BBNode)
    return false;

  for (const DomTreeNode *Node = BBNode->getIDom(); Node;
       Node = Node->getIDom()) {
    const BasicBlock *DBB = Node->getBlock();
    for (const Instruction &I : *DBB) {
      if (isNonnullAssume(I, Base))
        return true;
    }
  }
  return false;
}

static bool isDefinitelyNonnullValueAt(const Value *V, const Instruction *At,
                                       DominatorTree &DT) {
  std::unordered_set<ValueAtKey, ValueAtKeyHash> Visited;
  return isDefinitelyNonnullValueAtImpl(V, At, DT, Visited);
}

static bool isDefinitelyNonnullValueAtImpl(
    const Value *V, const Instruction *At, DominatorTree &DT,
    std::unordered_set<ValueAtKey, ValueAtKeyHash> &Visited) {
  if (!V || !At)
    return false;
  if (isNonnullPointerConstant(V))
    return true;
  V = stripTrackedValue(V);
  if (!V)
    return false;
  if (!Visited.insert(ValueAtKey{V, At}).second)
    return false;
  if (isNullConstant(V))
    return false;

  if (isa<Constant>(V))
    return V->getType()->isPointerTy();

  if (isValueNonnullAtInstruction(V, At, DT))
    return true;

  if (const auto *SI = dyn_cast<SelectInst>(V)) {
    if (isDefinitelyNonnullValueAtImpl(SI->getTrueValue(), At, DT, Visited) &&
        isDefinitelyNonnullValueAtImpl(SI->getFalseValue(), At, DT, Visited))
      return true;

    bool TrueMeansNonnull = false;
    if (matchNonnullCondition(SI->getCondition(), SI->getTrueValue(),
                              TrueMeansNonnull) &&
        TrueMeansNonnull &&
        isDefinitelyNonnullValueAtImpl(SI->getFalseValue(), At, DT, Visited))
      return true;
    if (matchNonnullCondition(SI->getCondition(), SI->getFalseValue(),
                              TrueMeansNonnull) &&
        !TrueMeansNonnull &&
        isDefinitelyNonnullValueAtImpl(SI->getTrueValue(), At, DT, Visited))
      return true;
  }

  if (const auto *PN = dyn_cast<PHINode>(V)) {
    if (PN->getParent() != At->getParent())
      return false;
    for (unsigned I = 0; I < PN->getNumIncomingValues(); ++I) {
      const BasicBlock *Pred = PN->getIncomingBlock(I);
      const Instruction *PredTerm = Pred->getTerminator();
      if (!PredTerm ||
          !isDefinitelyNonnullValueAtImpl(PN->getIncomingValue(I), PredTerm, DT,
                                          Visited))
        return false;
    }
    return true;
  }

  return false;
}

static bool isAllocatorName(StringRef Name, std::string &Kind) {
  if (Name.startswith("memdup") || Name.startswith("vmemdup_user") ||
      Name.startswith("kmemdup") || Name.startswith("kmemdup_nul") ||
      Name.startswith("strndup_user")) {
    return false;
  }

  static const std::pair<const char *, const char *> Names[] = {
      {"kmalloc", "kmalloc"},
      {"kmalloc_obj", "kmalloc"},
      {"kmalloc_node", "kmalloc"},
      {"kmalloc_nolock", "kmalloc"},
      {"kzalloc", "kzalloc"},
      {"kzalloc_obj", "kzalloc"},
      {"kzalloc_node", "kzalloc"},
      {"kcalloc", "kcalloc"},
      {"kcalloc_node", "kcalloc"},
      {"krealloc", "krealloc"},
      {"krealloc_array", "krealloc"},
      {"kvmalloc", "kvmalloc"},
      {"kvmalloc_array", "kvmalloc"},
      {"kvzalloc", "kvzalloc"},
      {"kvcalloc", "kvcalloc"},
      {"vmalloc", "vmalloc"},
      {"vzalloc", "vzalloc"},
      {"vcalloc", "vcalloc"},
      {"kmem_cache_alloc", "kmem_cache_alloc"},
      {"kmem_cache_alloc_node", "kmem_cache_alloc"},
      {"kmem_cache_zalloc", "kmem_cache_alloc"},
      {"kstrdup", "kstrdup"},
      {"kstrndup", "kstrndup"},
      {"kasprintf", "kasprintf"},
      {"kvasprintf", "kvasprintf"},
      {"devm_kmalloc", "devm_kmalloc"},
      {"devm_kzalloc", "devm_kzalloc"},
      {"devm_kcalloc", "devm_kcalloc"},
      {"devm_krealloc", "devm_krealloc"},
      {"devm_kstrdup", "devm_kstrdup"},
      {"devm_kasprintf", "devm_kasprintf"},
      {"dma_alloc", "dma_alloc"},
      {"usb_alloc", "usb_alloc"},
      {"__kmalloc", "__kmalloc"},
      {"__kmalloc_node", "__kmalloc"},
      {"__kzalloc", "__kzalloc"},
      {"__vmalloc", "__vmalloc"},
      {"__kvmalloc", "__kvmalloc"},
      {"__krealloc", "__krealloc"},
      {"__kmalloc_cache_noprof", "__kmalloc"},
      {"kmalloc_noprof", "__kmalloc"},
      {"kmalloc_node_noprof", "__kmalloc"},
      {"kzalloc_noprof", "__kzalloc"},
      {"kcalloc_noprof", "__kmalloc"},
      {"krealloc_noprof", "__krealloc"},
      {"kmem_cache_alloc_noprof", "kmem_cache_alloc"},
      {"kmem_cache_alloc_node_noprof", "kmem_cache_alloc"},
      {"kmem_cache_zalloc_noprof", "kmem_cache_alloc"},
      {"krealloc_node_align_noprof", "__krealloc"},
      {"__kmalloc_node_track_caller_noprof", "__kmalloc"},
      {"kzalloc_node_noprof", "__kzalloc"},
  };

  for (const auto &Entry : Names) {
    if (Name == Entry.first) {
      Kind = Entry.second;
      return true;
    }
  }
  return false;
}

static bool isPreferredOuterAllocatorWrapper(StringRef FuncName) {
  if (FuncName.startswith("__"))
    return false;
  std::string Kind;
  return isAllocatorName(FuncName, Kind);
}

static bool isExcludedDupFamily(StringRef Name) {
  return Name.startswith("memdup") || Name.startswith("vmemdup_user") ||
         Name.startswith("kmemdup") || Name.startswith("kmemdup_nul") ||
         Name.startswith("strndup_user");
}

static bool isFreeLikeFunction(StringRef Name) {
  static const char *Prefixes[] = {
      "kfree",         "kvfree",        "vfree",          "kvfree_sensitive",
      "kfree_sensitive","	kfree_rcu",    "kmem_cache_free","free_percpu",
      "kzfree",        "kfree_const",   "kvfree_rcu",     "vfree_atomic"};
  for (const char *Prefix : Prefixes) {
    if (Name.startswith(Prefix))
      return true;
  }
  return false;
}

static bool isAllocatorImplementationFunction(StringRef Name) {
  if (isExcludedDupFamily(Name))
    return true;

  static const char *Prefixes[] = {
      "__kmalloc",      "kmalloc_noprof",    "kzalloc_noprof",
      "kcalloc_noprof", "krealloc_noprof",   "kmem_cache_alloc_noprof",
      "__do_kmalloc",   "kmalloc_trace",     "kfree_sensitive",
      "__kvmalloc",     "__vmalloc",         "slab_",
      "__slab",         "kmalloc_large",     "kmalloc_order",
      "kvmalloc_node"};

  for (const char *Prefix : Prefixes) {
    if (Name.startswith(Prefix))
      return true;
  }
  return false;
}

static Function *resolveDirectCallee(Function *F, AnalysisState &State) {
  if (!F)
    return nullptr;
  if (!F->isDeclaration())
    return F;
  auto It = State.Definitions.find(F->getName().str());
  if (It == State.Definitions.end())
    return F;
  return It->second.F;
}

static bool isInterestingDeclSink(const CallBase &CB, unsigned ArgNo) {
  Function *Callee = CB.getCalledFunction();
  if (!Callee)
    return false;
  if (isFreeLikeFunction(Callee->getName()))
    return false;
  if (Callee->isIntrinsic()) {
    switch (Callee->getIntrinsicID()) {
    case Intrinsic::memcpy:
    case Intrinsic::memmove:
    case Intrinsic::memset:
      return ArgNo == 0;
    default:
      break;
    }
  }

  StringRef Name = Callee->getName();
  if ((Name.startswith("memcpy") || Name.startswith("memmove") ||
       Name.startswith("memset") || Name.startswith("strcpy") ||
       Name.startswith("strscpy") || Name.startswith("strlcpy")) &&
      ArgNo == 0)
    return true;
  return false;
}

static bool isPointerDerefSink(const Value *Tracked, const Instruction &I,
                               std::string &Kind,
                               const Value *&DerefValue) {
  if (auto *LI = dyn_cast<LoadInst>(&I)) {
    if (sameTrackedValue(LI->getPointerOperand(), Tracked)) {
      Kind = "load";
      DerefValue = LI->getPointerOperand();
      return true;
    }
  }
  if (auto *SI = dyn_cast<StoreInst>(&I)) {
    if (sameTrackedValue(SI->getPointerOperand(), Tracked)) {
      Kind = "store";
      DerefValue = SI->getPointerOperand();
      return true;
    }
  }
  if (auto *RMW = dyn_cast<AtomicRMWInst>(&I)) {
    if (sameTrackedValue(RMW->getPointerOperand(), Tracked)) {
      Kind = "atomicrmw";
      DerefValue = RMW->getPointerOperand();
      return true;
    }
  }
  if (auto *CX = dyn_cast<AtomicCmpXchgInst>(&I)) {
    if (sameTrackedValue(CX->getPointerOperand(), Tracked)) {
      Kind = "cmpxchg";
      DerefValue = CX->getPointerOperand();
      return true;
    }
  }
  if (auto *CB = dyn_cast<CallBase>(&I)) {
    for (unsigned ArgNo = 0; ArgNo < CB->arg_size(); ++ArgNo) {
      if (!sameTrackedValue(CB->getArgOperand(ArgNo), Tracked))
        continue;
      if (isInterestingDeclSink(*CB, ArgNo)) {
        Kind = "call-arg-deref";
        DerefValue = CB->getArgOperand(ArgNo);
        return true;
      }
    }
  }
  return false;
}

static std::string functionNameOrUnknown(const Function *F) {
  return F ? F->getName().str() : "<unknown>";
}

static void appendCallStep(SmallVectorImpl<std::string> &Chain,
                           const Function *Caller, const Function *Callee,
                           const Instruction *At) {
  std::string Step = functionNameOrUnknown(Caller) + " -> " +
                     functionNameOrUnknown(Callee) + " @ " + formatDebugLoc(At);
  Chain.push_back(std::move(Step));
}

static void deduplicateReports(std::vector<Report> &Reports) {
  logPhase("post-processing reports: deduplicating " +
           std::to_string(Reports.size()) + " raw reports");
  std::vector<Report> Unique;
  Unique.reserve(Reports.size());
  std::unordered_set<ReportKey, ReportKeyHash> Seen;
  Seen.reserve(Reports.size() * 2 + 1);

  for (Report &R : Reports) {
    ReportKey Key;
    Key.SourceSite = R.Src ? R.Src->SourceSite : nullptr;
    Key.SourceFunction = R.Src ? R.Src->SourceFunction : nullptr;
    Key.SourceKind = R.Src ? R.Src->SourceKind : std::string();
    if (Seen.insert(std::move(Key)).second)
      Unique.push_back(std::move(R));
  }
  Reports.swap(Unique);
  logPhase("post-processing reports: " + std::to_string(Reports.size()) +
           " unique reports");
}

static bool shouldSkipFunction(const Function &F) {
  if (F.isDeclaration() || F.empty())
    return true;
  if (F.hasSection() && F.getSection() == ".init.text")
    return true;
  return false;
}

struct LocalCaches {
  DenseMap<const Function *, std::unique_ptr<DominatorTree>> DTs;

  DominatorTree &getDT(const Function *F) {
    auto It = DTs.find(F);
    if (It != DTs.end())
      return *It->second;
    auto DT = std::make_unique<DominatorTree>(*const_cast<Function *>(F));
    DominatorTree &Ref = *DT;
    DTs[F] = std::move(DT);
    return Ref;
  }
};

} // namespace

static constexpr uint64_t GFPNoFailBit = 1ULL << 15;

static bool valueMayBeNullFromReturns(
    const Value *V, AnalysisState &State,
    SmallPtrSetImpl<const Value *> &Visited);

std::string formatDebugLoc(const Instruction *I) {
  if (!I)
    return "<no-inst>";
  if (const DebugLoc &DL = I->getDebugLoc())
    return (DL->getFilename() + ":" + Twine(DL.getLine())).str();
  return "<no-debug>";
}

std::string formatValue(const Value *V) {
  if (!V)
    return "<null>";
  std::string S;
  raw_string_ostream OS(S);
  V->printAsOperand(OS, false);
  return OS.str();
}

static const ConstantInt *asIntegerConstant(const Value *V) {
  V = V->stripPointerCasts();
  if (auto *CI = dyn_cast<ConstantInt>(V))
    return CI;
  if (auto *CE = dyn_cast<ConstantExpr>(V)) {
    if (CE->isCast())
      return dyn_cast<ConstantInt>(CE->getOperand(0));
  }
  return nullptr;
}

static bool valueHasNoFailBit(
    const Value *V,
    const std::unordered_map<Function *, SmallVector<CallBase *, 16>> &Callers,
    SmallPtrSetImpl<const Value *> &Visited);

static bool anyCallerPassesNoFail(
    const Argument *Arg,
    const std::unordered_map<Function *, SmallVector<CallBase *, 16>> &Callers,
    SmallPtrSetImpl<const Value *> &Visited) {
  const Function *F = Arg->getParent();
  auto It = Callers.find(const_cast<Function *>(F));
  if (It == Callers.end())
    return false;

  unsigned ArgNo = Arg->getArgNo();
  for (CallBase *CallerCB : It->second) {
    if (ArgNo >= CallerCB->arg_size())
      continue;
    if (valueHasNoFailBit(CallerCB->getArgOperand(ArgNo), Callers, Visited))
      return true;
  }
  return false;
}

static bool valueHasNoFailBit(
    const Value *V,
    const std::unordered_map<Function *, SmallVector<CallBase *, 16>> &Callers,
    SmallPtrSetImpl<const Value *> &Visited) {
  V = V->stripPointerCasts();
  if (!Visited.insert(V).second)
    return false;

  if (const ConstantInt *CI = asIntegerConstant(V))
    return (CI->getZExtValue() & GFPNoFailBit) != 0;

  if (const auto *Arg = dyn_cast<Argument>(V))
    return anyCallerPassesNoFail(Arg, Callers, Visited);

  if (const auto *BO = dyn_cast<BinaryOperator>(V)) {
    switch (BO->getOpcode()) {
    case Instruction::Or:
    case Instruction::And:
      return valueHasNoFailBit(BO->getOperand(0), Callers, Visited) ||
             valueHasNoFailBit(BO->getOperand(1), Callers, Visited);
    default:
      break;
    }
  }

  if (const auto *PN = dyn_cast<PHINode>(V)) {
    for (const Value *Incoming : PN->incoming_values()) {
      if (valueHasNoFailBit(Incoming, Callers, Visited))
        return true;
    }
    return false;
  }

  if (const auto *SI = dyn_cast<SelectInst>(V))
    return valueHasNoFailBit(SI->getTrueValue(), Callers, Visited) ||
           valueHasNoFailBit(SI->getFalseValue(), Callers, Visited);

  if (const auto *I = dyn_cast<Instruction>(V)) {
    if (isa<ZExtInst>(I) || isa<SExtInst>(I) || isa<TruncInst>(I)) {
      return valueHasNoFailBit(I->getOperand(0), Callers, Visited);
    }
  }

  return false;
}

static int getGFPArgIndex(StringRef AllocName, unsigned ArgCount) {
  if (ArgCount == 0)
    return -1;
  if (AllocName.startswith("kasprintf") || AllocName.startswith("kvasprintf"))
    return 0;
  if (AllocName.startswith("__kmalloc_cache_noprof"))
    return ArgCount > 1 ? 1 : -1;
  if (AllocName.startswith("kmalloc") || AllocName.startswith("kzalloc") ||
      AllocName.startswith("kcalloc") || AllocName.startswith("krealloc") ||
      AllocName.startswith("kvmalloc") || AllocName.startswith("kvzalloc") ||
      AllocName.startswith("kvcalloc") || AllocName.startswith("vmalloc") ||
      AllocName.startswith("vzalloc") || AllocName.startswith("vcalloc") ||
      AllocName.startswith("kstrdup") || AllocName.startswith("kstrndup") ||
      AllocName.startswith("kmemdup") || AllocName.startswith("kmemdup_nul") ||
      AllocName.startswith("memdup") || AllocName.startswith("vmemdup_user") ||
      AllocName.startswith("strndup_user") || AllocName.startswith("__kmalloc") ||
      AllocName.startswith("__kzalloc") || AllocName.startswith("__vmalloc") ||
      AllocName.startswith("__kvmalloc") || AllocName.startswith("__krealloc") ||
      AllocName.startswith("devm_kmalloc") ||
      AllocName.startswith("devm_kzalloc") ||
      AllocName.startswith("devm_kcalloc") ||
      AllocName.startswith("devm_krealloc") ||
      AllocName.startswith("devm_kstrdup") ||
      AllocName.startswith("devm_kmemdup") ||
      AllocName.startswith("devm_kasprintf") ||
      AllocName.startswith("kmem_cache_alloc") ||
      AllocName.startswith("kmem_cache_zalloc"))
    return static_cast<int>(ArgCount) - 1;
  return -1;
}

static bool memoryObjectHasPanicBit(const Value *V,
                                    SmallPtrSetImpl<const Value *> &Visited) {
  V = V->stripPointerCasts();
  if (!Visited.insert(V).second)
    return false;

  for (const User *U : V->users()) {
    if (const auto *SI = dyn_cast<StoreInst>(U)) {
      if (SI->getPointerOperand()->stripPointerCasts() != V)
        continue;
      if (const ConstantInt *CI = asIntegerConstant(SI->getValueOperand())) {
        if ((CI->getZExtValue() & 8ULL) != 0)
          return true;
      }
      continue;
    }

    if (isa<GetElementPtrInst>(U) || isa<BitCastInst>(U) ||
        isa<AddrSpaceCastInst>(U)) {
      if (memoryObjectHasPanicBit(cast<Value>(U), Visited))
        return true;
    }
  }

  return false;
}

static bool cacheValueIsPanic(const Value *V, AnalysisState &State,
                              SmallPtrSetImpl<const Value *> &Visited) {
  V = V->stripPointerCasts();
  if (!Visited.insert(V).second)
    return false;

  if (State.PanicSlabCaches.count(V))
    return true;

  if (const auto *LI = dyn_cast<LoadInst>(V))
    return cacheValueIsPanic(LI->getPointerOperand(), State, Visited);

  if (const auto *Arg = dyn_cast<Argument>(V)) {
    auto It = State.Callers.find(const_cast<Function *>(Arg->getParent()));
    if (It == State.Callers.end())
      return false;
    for (CallBase *CallerCB : It->second) {
      if (Arg->getArgNo() >= CallerCB->arg_size())
        continue;
      if (cacheValueIsPanic(CallerCB->getArgOperand(Arg->getArgNo()), State,
                            Visited))
        return true;
    }
    return false;
  }

  if (const auto *PN = dyn_cast<PHINode>(V)) {
    for (const Value *Incoming : PN->incoming_values()) {
      if (cacheValueIsPanic(Incoming, State, Visited))
        return true;
    }
    return false;
  }

  if (const auto *SI = dyn_cast<SelectInst>(V))
    return cacheValueIsPanic(SI->getTrueValue(), State, Visited) ||
           cacheValueIsPanic(SI->getFalseValue(), State, Visited);

  return false;
}

static bool allocatorIsNoFail(
    const CallBase &CB, StringRef AllocName, AnalysisState &State) {
  if (AllocName.startswith("kmem_cache_alloc")) {
    SmallPtrSet<const Value *, 16> CacheVisited;
    if (!CB.arg_empty() &&
        cacheValueIsPanic(CB.getArgOperand(0), State, CacheVisited))
      return true;
  }

  int GFPArgIndex = getGFPArgIndex(AllocName, CB.arg_size());
  if (GFPArgIndex < 0 || static_cast<unsigned>(GFPArgIndex) >= CB.arg_size())
    return false;
  SmallPtrSet<const Value *, 32> Visited;
  return valueHasNoFailBit(CB.getArgOperand(GFPArgIndex), State.Callers,
                           Visited);
}

static bool valueEscapesThroughMemoryOrCall(
    const Value *V, SmallPtrSetImpl<const Value *> &Visited) {
  V = stripTrackedValue(V);
  if (!Visited.insert(V).second)
    return false;

  for (const User *U : V->users()) {
    if (const auto *CB = dyn_cast<CallBase>(U)) {
      for (const Value *Arg : CB->args()) {
        if (Arg == V)
          return true;
      }
      continue;
    }

    if (const auto *SI = dyn_cast<StoreInst>(U)) {
      if (SI->getValueOperand() == V)
        return true;
      continue;
    }

    if (isa<BitCastInst>(U) || isa<AddrSpaceCastInst>(U) ||
        isa<GetElementPtrInst>(U) || isa<PHINode>(U) || isa<SelectInst>(U) ||
        isa<FreezeInst>(U)) {
      if (valueEscapesThroughMemoryOrCall(cast<Value>(U), Visited))
        return true;
    }
  }

  return false;
}

static bool isIgnoredPath(StringRef Path) {
  static const char *Pieces[] = {
      "/tools/",       "/security/",   "/mm/kasan/", "/mm/kfence/",
      "/kernel/kcov.c","/kernel/kcsan/","/kernel/kfence/"};
  for (const char *Piece : Pieces) {
    if (Path.contains(Piece))
      return true;
  }
  return false;
}

static bool isIgnoredSourceKind(StringRef Kind) {
  return Kind == "vmalloc_to_page" || Kind == "debugfs_create_dir" ||
         Kind == "hlock_class";
}

static StringRef getModulePath(const Function *F, AnalysisState &State) {
  auto It = State.FunctionInfo.find(const_cast<Function *>(F));
  if (It == State.FunctionInfo.end())
    return StringRef();
  return It->second.ModulePath;
}

static bool blockContainsWarningLikePath(const BasicBlock *BB) {
  for (const Instruction &I : *BB) {
    const auto *CB = dyn_cast<CallBase>(&I);
    if (!CB)
      continue;

    if (const auto *IA = dyn_cast<InlineAsm>(CB->getCalledOperand())) {
      StringRef Asm = IA->getAsmString();
      if (Asm.contains("ud2") || Asm.contains("__bug_table"))
        return true;
      continue;
    }

    const Function *Callee = CB->getCalledFunction();
    if (!Callee)
      continue;
    StringRef Name = Callee->getName();
    if (Name.contains("warn") || Name.contains("WARN") ||
        Name.contains("bug") || Name.contains("BUG"))
      return true;
  }
  return false;
}

static bool returnValueMayBeNull(const ReturnInst *RI, const Value *RetVal,
                                 AnalysisState &State, DominatorTree &DT) {
  if (const auto *PN = dyn_cast<PHINode>(RetVal)) {
    if (PN->getParent() == RI->getParent()) {
      for (unsigned I = 0; I < PN->getNumIncomingValues(); ++I) {
        const Value *Incoming = PN->getIncomingValue(I);
        const BasicBlock *Pred = PN->getIncomingBlock(I);
        if (isNullConstant(Incoming) && blockContainsWarningLikePath(Pred))
          continue;
        const Instruction *At = Pred->getTerminator();
        if (At && isDefinitelyNonnullValueAt(Incoming, At, DT))
          continue;

        SmallPtrSet<const Value *, 32> Visited;
        if (valueMayBeNullFromReturns(Incoming, State, Visited))
          return true;
      }
      return false;
    }
  }

  if (isDefinitelyNonnullValueAt(RetVal, RI, DT))
    return false;

  if (isNullConstant(RetVal) && blockContainsWarningLikePath(RI->getParent()))
    return false;

  SmallPtrSet<const Value *, 32> Visited;
  return valueMayBeNullFromReturns(RetVal, State, Visited);
}

static bool valueMayBeNullFromReturns(
    const Value *V, AnalysisState &State,
    SmallPtrSetImpl<const Value *> &Visited) {
  V = stripTrackedValue(V);
  if (!Visited.insert(V).second)
    return false;

  if (isNullConstant(V))
    return true;

  if (const auto *CB = dyn_cast<CallBase>(V)) {
    Function *Callee = resolveDirectCallee(CB->getCalledFunction(), State);
    if (Callee) {
      std::string Kind;
      if (isAllocatorName(Callee->getName(), Kind) &&
          !allocatorIsNoFail(*CB, Callee->getName(), State))
        return true;
      if (State.MayReturnNullFunctions.count(Callee))
        return true;
    }
    return false;
  }

  if (const auto *PN = dyn_cast<PHINode>(V)) {
    for (const Value *Incoming : PN->incoming_values()) {
      if (valueMayBeNullFromReturns(Incoming, State, Visited))
        return true;
    }
    return false;
  }

  if (const auto *SI = dyn_cast<SelectInst>(V))
    return valueMayBeNullFromReturns(SI->getTrueValue(), State, Visited) ||
           valueMayBeNullFromReturns(SI->getFalseValue(), State, Visited);

  if (const auto *LI = dyn_cast<LoadInst>(V)) {
    const Value *Ptr = LI->getPointerOperand()->stripPointerCasts();
    if (const auto *AI = dyn_cast<AllocaInst>(Ptr)) {
      bool SawStore = false;
      for (const User *U : AI->users()) {
        const auto *Store = dyn_cast<StoreInst>(U);
        if (!Store || Store->getPointerOperand()->stripPointerCasts() != AI)
          continue;
        SawStore = true;
        if (valueMayBeNullFromReturns(Store->getValueOperand(), State, Visited))
          return true;
      }
      if (SawStore)
        return false;

      SmallPtrSet<const Value *, 32> EscapeVisited;
      if (valueEscapesThroughMemoryOrCall(AI, EscapeVisited))
        return false;
      return true;
    }
  }

  return false;
}

bool loadModules(const std::vector<std::string> &Paths, AnalysisState &State,
                 std::string &Error) {
  SMDiagnostic Err;
  for (const std::string &Path : Paths) {
    auto Ctx = std::make_unique<LLVMContext>();
    std::unique_ptr<Module> M = parseIRFile(Path, Err, *Ctx);
    if (!M) {
      Error = "failed to load '" + Path + "'";
      return false;
    }

    for (Function &F : *M) {
      if (F.isDeclaration())
        continue;
      FunctionRecord R;
      R.F = &F;
      R.M = M.get();
      R.ModulePath = Path;
      State.FunctionInfo[&F] = R;
      State.Definitions[F.getName().str()] = R;
    }

    State.Contexts.push_back(std::move(Ctx));
    State.Modules.push_back(std::move(M));
  }
  return true;
}

void collectPanicSlabCaches(AnalysisState &State) {
  for (const auto &ModulePtr : State.Modules) {
    for (Function &F : *ModulePtr) {
      if (shouldSkipFunction(F))
        continue;
      for (Instruction &I : instructions(F)) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB)
          continue;
        Function *Callee = resolveDirectCallee(CB->getCalledFunction(), State);
        if (!Callee || Callee->getName() != "__kmem_cache_create_args")
          continue;

        bool IsPanic = false;
        for (const Value *Arg : CB->args()) {
          if (const ConstantInt *CI = asIntegerConstant(Arg)) {
            if ((CI->getZExtValue() & 8ULL) != 0) {
              IsPanic = true;
              break;
            }
          }
        }
        if (!IsPanic && CB->arg_size() > 2) {
          SmallPtrSet<const Value *, 16> Visited;
          IsPanic = memoryObjectHasPanicBit(CB->getArgOperand(2), Visited);
        }
        if (!IsPanic)
          continue;

        for (const User *U : CB->users()) {
          const auto *SI = dyn_cast<StoreInst>(U);
          if (!SI || SI->getValueOperand() != CB)
            continue;
          State.PanicSlabCaches.insert(
              SI->getPointerOperand()->stripPointerCasts());
        }
      }
    }
  }
}

void buildCallers(AnalysisState &State) {
  for (const auto &ModulePtr : State.Modules) {
    for (Function &F : *ModulePtr) {
      if (shouldSkipFunction(F))
        continue;
      for (Instruction &I : instructions(F)) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB || CB->isIndirectCall())
          continue;
        Function *Callee = resolveDirectCallee(CB->getCalledFunction(), State);
        if (!Callee || Callee->isDeclaration())
          continue;
        State.Callers[Callee].push_back(CB);
      }
    }
  }
}

void computeMayReturnNullFunctions(AnalysisState &State) {
  LocalCaches Caches;
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (const auto &ModulePtr : State.Modules) {
      for (Function &F : *ModulePtr) {
        if (shouldSkipFunction(F) || !F.getReturnType()->isPointerTy())
          continue;
        if (State.MayReturnNullFunctions.count(&F))
          continue;

        bool MayReturnNull = false;
        DominatorTree &DT = Caches.getDT(&F);
        for (Instruction &I : instructions(F)) {
          auto *RI = dyn_cast<ReturnInst>(&I);
          if (!RI)
            continue;
          const Value *RetVal = RI->getReturnValue();
          if (!RetVal) {
            MayReturnNull = true;
            break;
          }
          if (returnValueMayBeNull(RI, RetVal, State, DT)) {
            MayReturnNull = true;
            break;
          }
        }

        if (!MayReturnNull)
          continue;
        State.MayReturnNullFunctions.insert(&F);
        Changed = true;
      }
    }
  }
}

void collectSources(AnalysisState &State) {
  for (const auto &ModulePtr : State.Modules) {
    for (Function &F : *ModulePtr) {
      if (shouldSkipFunction(F))
        continue;
      if (isIgnoredPath(getModulePath(&F, State)))
        continue;
      if (isAllocatorImplementationFunction(F.getName()))
        continue;
      for (Instruction &I : instructions(F)) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB || !CB->getType()->isPointerTy())
          continue;

        Function *Callee = resolveDirectCallee(CB->getCalledFunction(), State);
        if (!Callee)
          continue;

        std::string Kind;
        bool IsSource = false;
        if (isAllocatorName(Callee->getName(), Kind)) {
          if (Callee->getName().startswith("__") &&
              isPreferredOuterAllocatorWrapper(F.getName()))
            continue;
          if (allocatorIsNoFail(*CB, Callee->getName(), State))
            continue;
          IsSource = true;
        } else if (State.MayReturnNullFunctions.count(Callee)) {
          Kind = Callee->getName().str();
          IsSource = true;
        }
        if (!IsSource)
          continue;
        if (isIgnoredSourceKind(Kind))
          continue;
        if (isIgnoredPath(formatDebugLoc(&I)))
          continue;
        if (hasNullComparisonInValueFlow(CB, &State.Callers))
          continue;

        Source Src;
        Src.SourceSite = &I;
        Src.SourceFunction = &F;
        Src.SourceKind = Kind;
        State.Sources.push_back(std::move(Src));
      }
    }
  }
}

void analyzeSources(AnalysisState &State) {
  LocalCaches Caches;

  for (size_t SrcIdx = 0; SrcIdx < State.Sources.size(); ++SrcIdx) {
    logProgress("analyzing sources", SrcIdx + 1, State.Sources.size());
    const Source &Src = State.Sources[SrcIdx];

    std::deque<WorkItem> Queue;
    std::unordered_set<StateKey, StateKeyHash> Seen;
    size_t Visits = 0;

    WorkItem Seed;
    Seed.Tracked = Src.SourceSite;
    Seed.Context = Src.SourceFunction;
    Queue.push_back(std::move(Seed));

    while (!Queue.empty() && Visits < MaxVisitsPerSource) {
      WorkItem Item = std::move(Queue.front());
      Queue.pop_front();

      StateKey Key{Item.Tracked, Item.Context, Item.IsMemory, Item.Depth};
      if (!Seen.insert(Key).second)
        continue;
      ++Visits;

      if (Item.IsMemory) {
        const AllocaInst *Slot = asTrackedStackSlot(Item.Tracked);
        if (!Slot)
          continue;
        for (const User *U : Item.Tracked->users()) {
          auto *LI = dyn_cast<LoadInst>(U);
          if (!LI)
            continue;
          if (LI->getPointerOperand()->stripPointerCasts() != Slot)
            continue;
          Queue.push_back(WorkItem{LI, Item.Context, false, Item.Depth,
                                   Item.CallChain});
        }
        continue;
      }

      const Value *Tracked = Item.Tracked;
      const Function *Context = Item.Context;
      if (!Context)
        continue;
      DominatorTree &DT = Caches.getDT(Context);

      for (const User *U : Tracked->users()) {
        const auto *UserI = dyn_cast<Instruction>(U);
        if (!UserI)
          continue;
        if (UserI->getFunction() != Context)
          continue;

        std::string SinkKind;
        const Value *DerefValue = nullptr;
        if (isPointerDerefSink(Tracked, *UserI, SinkKind, DerefValue) &&
            !isDefinitelyNonnullValueAt(DerefValue ? DerefValue : Tracked, UserI,
                                        DT) &&
            !isValueNonnullAtInstruction(Tracked, UserI, DT)) {
          Report R;
          R.Src = &Src;
          R.Sink = UserI;
          R.SinkFunction = const_cast<Function *>(UserI->getFunction());
          R.SinkKind = SinkKind;
          R.CallChain = Item.CallChain;
          State.Reports.push_back(std::move(R));
        }

        if (isa<BitCastInst>(UserI) || isa<AddrSpaceCastInst>(UserI) ||
            isa<GetElementPtrInst>(UserI) || isa<PHINode>(UserI) ||
            isa<SelectInst>(UserI) || isa<FreezeInst>(UserI)) {
          Queue.push_back(WorkItem{UserI, Context, false, Item.Depth,
                                   Item.CallChain});
          continue;
        }

        if (auto *SI = dyn_cast<StoreInst>(UserI)) {
          if (sameTrackedValue(SI->getValueOperand(), Tracked)) {
            const AllocaInst *Slot =
                asTrackedStackSlot(SI->getPointerOperand());
            if (Slot) {
              Queue.push_back(
                  WorkItem{Slot, Context, true, Item.Depth, Item.CallChain});
            }
          }
          continue;
        }

        if (auto *CB = dyn_cast<CallBase>(UserI)) {
          Function *Callee =
              resolveDirectCallee(CB->getCalledFunction(), State);
          for (unsigned ArgNo = 0; ArgNo < CB->arg_size(); ++ArgNo) {
            if (!sameTrackedValue(CB->getArgOperand(ArgNo), Tracked))
              continue;
            if (isValueNonnullAtInstruction(Tracked, CB, DT))
              continue;
            if (Callee && isFreeLikeFunction(Callee->getName()))
              continue;
            if (!Callee || Callee->isDeclaration() || ArgNo >= Callee->arg_size())
              continue;
            if (Item.Depth >= MaxCallDepth)
              continue;

            auto ArgIt = Callee->arg_begin();
            std::advance(ArgIt, ArgNo);
            SmallVector<std::string, 8> NextChain = Item.CallChain;
            appendCallStep(NextChain, Context, Callee, CB);
            Queue.push_back(
                WorkItem{&*ArgIt, Callee, false, Item.Depth + 1, NextChain});
          }
          continue;
        }

        if (auto *RI = dyn_cast<ReturnInst>(UserI)) {
          if (!sameTrackedValue(RI->getReturnValue(), Tracked))
            continue;
          auto CallersIt =
              State.Callers.find(const_cast<Function *>(cast<Function>(Context)));
          if (CallersIt == State.Callers.end())
            continue;

          for (CallBase *CallerCB : CallersIt->second) {
            if (Item.Depth >= MaxCallDepth)
              continue;
            SmallVector<std::string, 8> NextChain = Item.CallChain;
            appendCallStep(NextChain, Context, CallerCB->getFunction(), CallerCB);
            Queue.push_back(WorkItem{CallerCB, CallerCB->getFunction(), false,
                                     Item.Depth + 1, NextChain});
          }
        }
      }
    }
  }

  deduplicateReports(State.Reports);
  logPhase("post-processing reports: sorting");
  std::sort(State.Reports.begin(), State.Reports.end(),
            [](const Report &A, const Report &B) {
              auto AK = std::make_tuple(formatDebugLoc(A.Src->SourceSite),
                                        formatDebugLoc(A.Sink), A.SinkKind);
              auto BK = std::make_tuple(formatDebugLoc(B.Src->SourceSite),
                                        formatDebugLoc(B.Sink), B.SinkKind);
              return AK < BK;
            });
}

void writeReports(const AnalysisState &State, raw_ostream &OS) {
  OS << "malloc-checker reports: " << State.Reports.size() << "\n";
  for (size_t I = 0; I < State.Reports.size(); ++I) {
    const Report &R = State.Reports[I];
    OS << "\n[" << (I + 1) << "] unchecked nullable return use\n";
    OS << "  source-kind: " << R.Src->SourceKind << "\n";
    OS << "  source-func: " << functionNameOrUnknown(R.Src->SourceFunction)
       << "\n";
    OS << "  source-loc:  " << formatDebugLoc(R.Src->SourceSite) << "\n";
    OS << "  sink-func:  " << functionNameOrUnknown(R.SinkFunction) << "\n";
    OS << "  sink-kind:  " << R.SinkKind << "\n";
    OS << "  sink-loc:   " << formatDebugLoc(R.Sink) << "\n";
    if (!R.CallChain.empty()) {
      OS << "  call-chain:\n";
      for (const std::string &Step : R.CallChain)
        OS << "    " << Step << "\n";
    }
  }
}

} // namespace mallocchecker
