#include "IndirectCallResolver.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/raw_ostream.h"

#include <map>
#include <regex>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

namespace mallocchecker {

namespace {

// Map from struct element type-ids to struct names (for anonymous struct
// matching).
static std::map<std::string, std::set<StringRef>> ElementsStructNameMap;

static constexpr unsigned MAX_TYPE_LAYER = 10;
static constexpr unsigned MAX_ICALLEE_TARGETS = 50;

std::string structTyStr(StructType *STy) {
  std::string TyStr;
  for (auto *Ty : STy->elements())
    TyStr += std::to_string(Ty->getTypeID());
  return TyStr;
}

void cleanString(std::string &Str) {
  size_t Pos = Str.find("(%class.");
  if (Pos != std::string::npos) {
    std::regex Pattern("^[_A-Za-z0-9]+\\*,?");
    std::smatch Match;
    std::string Sub = Str.substr(Pos + 8);
    if (std::regex_search(Sub, Match, Pattern))
      Str.replace(Pos + 1, 7 + Match[0].length(), "");
  }
  auto EndIt = std::remove(Str.begin(), Str.end(), ' ');
  Str.erase(EndIt, Str.end());
}

} // namespace

TypeIntPair typeidx_c(Type *Ty, int Idx) { return std::make_pair(Ty, Idx); }
HashIntPair hashidx_c(size_t Hash, int Idx) {
  return std::make_pair(Hash, Idx);
}

bool isCompositeType(Type *Ty) {
  return Ty->isStructTy() || Ty->isArrayTy() || Ty->isVectorTy();
}

Type *getFuncPtrType(Value *V) {
  Type *Ty = V->getType();
  if (auto *PTy = dyn_cast<PointerType>(Ty)) {
    if (PTy->isOpaquePointerTy())
      return nullptr;
    Type *ETy = PTy->getPointerElementType();
    if (ETy->isFunctionTy())
      return ETy;
  }
  return nullptr;
}

Function *getBaseFunction(Value *V) {
  if (auto *F = dyn_cast<Function>(V))
    return F->isIntrinsic() ? nullptr : F;
  Value *CV = V;
  while (auto *BCO = dyn_cast<BitCastOperator>(CV)) {
    Value *O = BCO->getOperand(0);
    if (auto *F = dyn_cast<Function>(O))
      return F->isIntrinsic() ? nullptr : F;
    CV = O;
  }
  return nullptr;
}

void loadElementsStructNameMap(AnalysisState &State) {
  for (const auto &ModulePtr : State.Modules) {
    for (StructType *STy : ModulePtr->getIdentifiedStructTypes()) {
      if (!STy->hasName() || STy->isOpaque())
        continue;
      ElementsStructNameMap[structTyStr(STy)].insert(STy->getName());
    }
  }
}

// ---------------------------------------------------------------------------
// Hash functions
// ---------------------------------------------------------------------------

size_t funcHash(Function *F, bool WithName) {
  std::hash<std::string> StrHash;
  std::string Output;
  std::string Sig;
  raw_string_ostream RSO(Sig);
  F->getFunctionType()->print(RSO);
  Output = RSO.str();
  if (WithName)
    Output += F->getName().str();
  cleanString(Output);
  return StrHash(Output);
}

size_t callHash(CallBase *CB) {
  std::hash<std::string> StrHash;
  std::string Sig;
  raw_string_ostream RSO(Sig);
  CB->getFunctionType()->print(RSO);
  std::string StripStr = RSO.str();
  cleanString(StripStr);
  return StrHash(StripStr);
}

size_t typeHash(Type *Ty, AnalysisState &State) {
  std::hash<std::string> StrHash;
  std::string TyStr;

  if (auto *STy = dyn_cast<StructType>(Ty)) {
    if (STy->hasName()) {
      TyStr = STy->getName().str();
    } else {
      std::string SStr = structTyStr(STy);
      auto It = ElementsStructNameMap.find(SStr);
      if (It != ElementsStructNameMap.end())
        TyStr = It->second.begin()->str();
    }
  } else if (auto *ATy = dyn_cast<ArrayType>(Ty)) {
    Type *ElemTy = ATy->getElementType();
    std::string Sig;
    raw_string_ostream RSO(Sig);
    ElemTy->print(RSO);
    TyStr = RSO.str() + "[array]";
    auto EndIt = std::remove(TyStr.begin(), TyStr.end(), ' ');
    TyStr.erase(EndIt, TyStr.end());
  } else {
    std::string Sig;
    raw_string_ostream RSO(Sig);
    Ty->print(RSO);
    TyStr = RSO.str();
    auto EndIt = std::remove(TyStr.begin(), TyStr.end(), ' ');
    TyStr.erase(EndIt, TyStr.end());
  }
  return StrHash(TyStr);
}

void structTypeHash(StructType *STy, std::set<size_t> &HSet,
                    AnalysisState &State) {
  std::hash<std::string> StrHash;
  std::string TyStr;
  if (STy->hasName()) {
    TyStr = STy->getName().str();
    HSet.insert(StrHash(TyStr));
  } else {
    std::string SStr = structTyStr(STy);
    auto It = ElementsStructNameMap.find(SStr);
    if (It != ElementsStructNameMap.end()) {
      for (auto &SStrName : It->second)
        HSet.insert(StrHash(SStrName.str()));
    }
  }
}

size_t hashIdxHash(size_t Hs, int Idx) {
  std::hash<std::string> StrHash;
  return Hs + StrHash(std::to_string(Idx));
}

size_t typeIdxHash(Type *Ty, int Idx, AnalysisState &State) {
  return hashIdxHash(typeHash(Ty, State), Idx);
}

// ---------------------------------------------------------------------------
// Fuzzy type matching (cross-module conservative)
// ---------------------------------------------------------------------------

static Argument *getParamByArgNo(Function *F, unsigned ArgNo) {
  if (ArgNo >= F->arg_size())
    return nullptr;
  auto It = F->arg_begin();
  for (unsigned I = 0; I < ArgNo; ++I)
    ++It;
  return &*It;
}

bool fuzzyTypeMatch(Type *Ty1, Type *Ty2, Module *M1, Module *M2,
                    AnalysisState &State) {
  if (Ty1 == Ty2)
    return true;

  while (Ty1->isPointerTy() && Ty2->isPointerTy()) {
    Ty1 = Ty1->getPointerElementType();
    Ty2 = Ty2->getPointerElementType();
  }

  if (Ty1->isStructTy() && Ty2->isStructTy() &&
      Ty1->getStructName().equals(Ty2->getStructName()))
    return true;
  if (Ty1->isIntegerTy() && Ty2->isIntegerTy() &&
      Ty1->getIntegerBitWidth() == Ty2->getIntegerBitWidth())
    return true;

  // Conservative: general pointers (void*, char*) match anything.
  Type *I8PtrTy = Type::getInt8PtrTy(M1->getContext());
  Type *I8PtrTy2 = Type::getInt8PtrTy(M2->getContext());
  const DataLayout &DL2 = M2->getDataLayout();
  Type *IntPtrTy2 = DL2.getIntPtrType(M2->getContext());

  if ((Ty1 == I8PtrTy && (Ty2->isPointerTy() || Ty2 == IntPtrTy2)) ||
      (Ty2 == I8PtrTy2 && (Ty1->isPointerTy() ||
                            Ty1 == M1->getDataLayout().getIntPtrType(
                                        M1->getContext()))))
    return true;

  return false;
}

// ---------------------------------------------------------------------------
// Type traversal: getBaseType / nextLayerBaseType / getBaseTypeChain
// ---------------------------------------------------------------------------

static Type *getPhiBaseType(PHINode *PN, std::set<Value *> &Visited,
                            AnalysisState &State) {
  for (unsigned I = 0, E = PN->getNumIncomingValues(); I != E; ++I) {
    Type *BTy = getBaseType(PN->getIncomingValue(I), Visited, State);
    if (BTy)
      return BTy;
  }
  return nullptr;
}

Type *getBaseType(Value *V, std::set<Value *> &Visited,
                  AnalysisState &State) {
  if (!V)
    return nullptr;
  if (!Visited.insert(V).second)
    return nullptr;

  Type *Ty = V->getType();
  if (isCompositeType(Ty))
    return Ty;
  if (Ty->isPointerTy()) {
    Type *ETy = Ty->getPointerElementType();
    if (isCompositeType(ETy))
      return ETy;
  }

  if (auto *BCO = dyn_cast<BitCastOperator>(V))
    return getBaseType(BCO->getOperand(0), Visited, State);
  if (auto *SelI = dyn_cast<SelectInst>(V))
    return getBaseType(SelI->getTrueValue(), Visited, State);
  if (auto *PN = dyn_cast<PHINode>(V))
    return getPhiBaseType(PN, Visited, State);
  if (auto *LI = dyn_cast<LoadInst>(V))
    return getBaseType(LI->getPointerOperand(), Visited, State);

  return nullptr;
}

bool getGEPLayerTypes(GEPOperator *GEP, std::list<TypeIntPair> &TyList,
                      AnalysisState &State) {
  Value *PO = GEP->getPointerOperand();
  Type *ETy = GEP->getSourceElementType();

  std::vector<int> Indices;
  for (auto It = GEP->idx_begin(); It != GEP->idx_end(); ++It) {
    if (auto *ConstI = dyn_cast<ConstantInt>(It->get()))
      Indices.push_back(static_cast<int>(ConstI->getSExtValue()));
    else
      Indices.push_back(-1);
  }

  std::list<TypeIntPair> TmpTyList;
  for (auto It = Indices.begin() + 1; It != Indices.end(); ++It) {
    int Idx = *It;
    TmpTyList.push_front(typeidx_c(ETy, Idx));

    Type *SubTy = nullptr;
    if (auto *STy = dyn_cast<StructType>(ETy)) {
      if (Idx >= 0 && static_cast<unsigned>(Idx) < STy->getNumElements())
        SubTy = STy->getElementType(Idx);
      else
        return false;
    } else if (auto *ATy = dyn_cast<ArrayType>(ETy)) {
      SubTy = ATy->getElementType();
    } else if (auto *VTy = dyn_cast<VectorType>(ETy)) {
      SubTy = VTy->getElementType();
    }
    if (!SubTy)
      return false;
    ETy = SubTy;
  }

  // Handle struct base pointer alias for first field (compiler optimization --
  // base struct pointer acts as pointer to first field).
  if (auto *STy = dyn_cast<StructType>(ETy)) {
    if (STy->getNumElements() > 0) {
      Type *Ty0 = STy->getElementType(0);
      for (auto *U : GEP->users()) {
        if (auto *BCO = dyn_cast<BitCastOperator>(U)) {
          if (auto *PTy = dyn_cast<PointerType>(BCO->getType())) {
            if (Ty0 == PTy->getPointerElementType())
              TmpTyList.push_front(typeidx_c(ETy, 0));
          }
        }
      }
    }
  }

  if (!TmpTyList.empty()) {
    for (auto &TI : TmpTyList)
      TyList.push_back(TI);
    return true;
  }
  return false;
}

bool nextLayerBaseType(Value *V, std::list<TypeIntPair> &TyList,
                       Value *&NextV, AnalysisState &State) {
  if (!V || isa<Argument>(V)) {
    NextV = V;
    return false;
  }

  if (auto *GEP = dyn_cast<GEPOperator>(V)) {
    NextV = GEP->getPointerOperand();
    bool Ret = getGEPLayerTypes(GEP, TyList, State);
    if (!Ret)
      NextV = nullptr;
    return Ret;
  }
  if (auto *LI = dyn_cast<LoadInst>(V)) {
    NextV = LI->getPointerOperand();
    return nextLayerBaseType(LI->getOperand(0), TyList, NextV, State);
  }
  if (auto *BCO = dyn_cast<BitCastOperator>(V)) {
    NextV = BCO->getOperand(0);
    return nextLayerBaseType(BCO->getOperand(0), TyList, NextV, State);
  }
  // PHI and Select
  if (auto *PN = dyn_cast<PHINode>(V)) {
    bool Ret = false;
    for (unsigned I = 0, E = PN->getNumIncomingValues(); I != E; ++I) {
      Value *IV = PN->getIncomingValue(I);
      NextV = IV;
      std::list<TypeIntPair> NTyList;
      Ret = nextLayerBaseType(IV, NTyList, NextV, State);
      if (NTyList.size() > TyList.size())
        TyList = NTyList;
    }
    return Ret;
  }
  if (auto *SelI = dyn_cast<SelectInst>(V)) {
    NextV = SelI->getTrueValue();
    return nextLayerBaseType(SelI->getTrueValue(), TyList, NextV, State);
  }
  // UnaryOperator
  if (auto *UO = dyn_cast<UnaryOperator>(V)) {
    NextV = UO->getOperand(0);
    return nextLayerBaseType(UO->getOperand(0), TyList, NextV, State);
  }

  NextV = nullptr;
  return false;
}

bool getBaseTypeChain(std::list<TypeIntPair> &Chain, Value *V, bool &Complete,
                      AnalysisState &State) {
  Complete = true;
  Value *CV = V, *NextV = nullptr;
  std::list<TypeIntPair> TyList;
  std::set<Value *> Visited;

  Type *BTy = getBaseType(V, Visited, State);
  if (BTy)
    Chain.push_back(typeidx_c(BTy, 0));
  Visited.clear();

  while (nextLayerBaseType(CV, TyList, NextV, State))
    CV = NextV;

  for (auto &TI : TyList)
    Chain.push_back(typeidx_c(TI.first, TI.second));

  // Check completeness.
  if (!NextV)
    Complete = false;
  else if (isa<Argument>(NextV) && NextV->getType()->isPointerTy())
    Complete = false;
  else {
    for (auto *U : NextV->users()) {
      if (auto *SI = dyn_cast<StoreInst>(U)) {
        if (NextV == SI->getPointerOperand()) {
          Complete = false;
          break;
        }
      }
    }
  }

  if (!Chain.empty() && !Complete)
    State.TypeCapSet.insert(typeHash(Chain.back().first, State));

  return true;
}

// ---------------------------------------------------------------------------
// Type confinement
// ---------------------------------------------------------------------------

void confineTargetFunction(Value *V, Function *F, AnalysisState &State) {
  if (F->isIntrinsic())
    return;

  State.StoredFuncs.insert(F);

  std::list<TypeIntPair> TyChain;
  bool Complete = true;
  getBaseTypeChain(TyChain, V, Complete, State);
  for (auto &TI : TyChain) {
    State.TypeIdxFuncsMap[typeHash(TI.first, State)][TI.second].insert(F);
  }
  if (!Complete) {
    if (!TyChain.empty())
      State.TypeCapSet.insert(typeHash(TyChain.back().first, State));
    else
      State.TypeCapSet.insert(funcHash(F));
  }
}

bool typeConfineInInitializer(GlobalVariable *GV, AnalysisState &State) {
  Constant *Ini = GV->getInitializer();
  if (!isa<ConstantAggregate>(Ini))
    return false;

  std::map<Value *, std::pair<Value *, int>> ContainersMap;
  std::list<User *> LU;
  std::set<Value *> Visited;
  LU.push_back(Ini);

  while (!LU.empty()) {
    User *U = LU.front();
    LU.pop_front();
    if (!Visited.insert(U).second)
      continue;

    Type *UTy = U->getType();
    if (auto *STy = dyn_cast<StructType>(UTy)) {
      if (U->getNumOperands() > 0 &&
          STy->getNumElements() != U->getNumOperands())
        continue;
      else if (U->getNumOperands() == 0)
        continue;
    }

    for (auto OI = U->op_begin(), OE = U->op_end(); OI != OE; ++OI) {
      Value *O = *OI;
      Type *OTy = O->getType();
      ContainersMap[O] = std::make_pair(U, OI->getOperandNo());

      Function *FoundF = nullptr;

      // Case 1: direct function address
      if (auto *F = dyn_cast<Function>(O)) {
        FoundF = F;
      }
      // Case 2: composite-type assignment
      else if (isCompositeType(OTy)) {
        User *OU = dyn_cast<User>(O);
        LU.push_back(OU);
      }
      // Case 3: ptrtoint
      else if (auto *PIO = dyn_cast<PtrToIntOperator>(O)) {
        if (auto *F = dyn_cast<Function>(PIO->getOperand(0)))
          FoundF = F;
        else if (auto *OU = dyn_cast<User>(PIO->getOperand(0)))
          LU.push_back(OU);
      }
      // Case 4: bitcast of function
      else if (auto *CO = dyn_cast<BitCastOperator>(O)) {
        if (auto *CF = dyn_cast<Function>(CO->getOperand(0))) {
          if (!UTy->isStructTy())
            FoundF = CF;
        } else if (auto *OU = dyn_cast<User>(CO->getOperand(0))) {
          LU.push_back(OU);
        }
      }
      // Case 5: pointer to composite type
      else if (auto *POTy = dyn_cast<PointerType>(OTy)) {
        if (isa<ConstantPointerNull>(O))
          continue;
        User *OU = dyn_cast<User>(O);
        LU.push_back(OU);
        if (auto *GO = dyn_cast<GlobalVariable>(OU)) {
          Type *PTy = POTy->getPointerElementType();
          if (PTy->isStructTy())
            State.TypeCapSet.insert(typeHash(PTy, State));
        }
      }

      if (FoundF && !FoundF->isIntrinsic()) {
        if (GV->getName() != "llvm.compiler.used")
          State.StoredFuncs.insert(FoundF);

        Value *CV = O;
        std::set<Value *> ContainerVisited;
        while (ContainersMap.find(CV) != ContainersMap.end()) {
          auto Container = ContainersMap[CV];
          Type *CTy = Container.first->getType();
          std::set<size_t> TyHS;
          if (auto *STy = dyn_cast<StructType>(CTy))
            structTypeHash(STy, TyHS, State);
          else
            TyHS.insert(typeHash(CTy, State));

          for (size_t TyH : TyHS)
            State.TypeIdxFuncsMap[TyH][Container.second].insert(FoundF);

          if (!ContainerVisited.insert(CV).second)
            break;
          if (ContainerVisited.find(Container.first) != ContainerVisited.end())
            break;
          CV = Container.first;
        }
      }
    }
  }
  return true;
}

bool typeConfineInFunction(Function *F, AnalysisState &State) {
  for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
    Instruction *Ins = &*I;

    if (auto *SI = dyn_cast<StoreInst>(Ins)) {
      Value *VO = SI->getValueOperand();
      Function *CF = getBaseFunction(VO->stripPointerCasts());
      if (!CF || CF->isIntrinsic())
        continue;
      confineTargetFunction(SI->getPointerOperand(), CF, State);
    } else if (auto *CI = dyn_cast<CallInst>(Ins)) {
      for (auto OI = Ins->op_begin(), OE = Ins->op_end(); OI != OE; ++OI) {
        if (auto *CalledF = dyn_cast<Function>(*OI)) {
          if (CalledF->isIntrinsic())
            continue;
          if (CI->isIndirectCall()) {
            confineTargetFunction(*OI, CalledF, State);
            continue;
          }
          // Skip the called operand (index 0) for direct calls.
          if (OI->getOperandNo() == 0)
            continue;
          Value *CV = CI->getCalledOperand();
          auto *CF = dyn_cast<Function>(CV);
          if (!CF)
            continue;
          if (CF->isDeclaration()) {
            auto DefIt = State.Definitions.find(CF->getName().str());
            if (DefIt != State.Definitions.end())
              CF = DefIt->second.F;
          }
          if (!CF)
            continue;
          unsigned ArgNo = OI->getOperandNo() - 1;
          if (auto *Arg = getParamByArgNo(CF, ArgNo)) {
            for (auto *U : Arg->users())
              confineTargetFunction(U, CalledF, State);
          }
        }
      }
    } else if (auto *RI = dyn_cast<ReturnInst>(Ins)) {
      Value *RV = RI->getReturnValue();
      if (!RV)
        continue;
      auto *CF = dyn_cast<Function>(RV);
      if (!CF || CF->isIntrinsic())
        continue;
      confineTargetFunction(RI, CF, State);
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Type propagation
// ---------------------------------------------------------------------------

void propagateType(Value *ToV, Type *FromTy, int Idx, AnalysisState &State) {
  std::list<TypeIntPair> TyChain;
  bool Complete = true;
  getBaseTypeChain(TyChain, ToV, Complete, State);
  for (auto &T : TyChain) {
    if (typeHash(T.first, State) == typeHash(FromTy, State) && T.second == Idx)
      continue;
    State.TypeIdxPropMap[typeHash(T.first, State)][T.second].insert(
        hashidx_c(typeHash(FromTy, State), Idx));
  }
}

void escapeType(Value *V, AnalysisState &State) {
  std::list<TypeIntPair> TyChain;
  bool Complete = true;
  getBaseTypeChain(TyChain, V, Complete, State);
  for (auto &T : TyChain)
    State.TypeEscapeSet.insert(typeIdxHash(T.first, T.second, State));
}

bool typePropInFunction(Function *F, AnalysisState &State) {
  for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
    Instruction *Ins = &*I;

    Value *PO = nullptr, *VO = nullptr;
    if (auto *SI = dyn_cast<StoreInst>(Ins)) {
      PO = SI->getPointerOperand();
      VO = SI->getValueOperand();
    } else if (auto *CI = dyn_cast<CallInst>(Ins)) {
      Value *CV = CI->getCalledOperand();
      if (auto *CF = dyn_cast<Function>(CV)) {
        if (CF->getName() == "llvm.memcpy.p0i8.p0i8.i64") {
          PO = CI->getOperand(0);
          VO = CI->getOperand(1);
        }
      }
    }

    if (PO && VO) {
      if (isa<ConstantAggregate>(VO) || isa<ConstantData>(VO))
        continue;

      std::list<TypeIntPair> TyList;
      Value *NextV = nullptr;
      std::set<Value *> Visited;
      nextLayerBaseType(VO, TyList, NextV, State);
      if (!TyList.empty()) {
        for (auto &TI : TyList)
          propagateType(PO, TI.first, TI.second, State);
        continue;
      }

      Visited.clear();
      Type *BTy = getBaseType(VO, Visited, State);
      if (BTy) {
        propagateType(PO, BTy, State);
        continue;
      }

      Type *FTy = getFuncPtrType(VO->stripPointerCasts());
      if (FTy) {
        if (!getBaseFunction(VO))
          propagateType(PO, FTy, State);
        continue;
      }

      if (!VO->getType()->isPointerTy())
        continue;
      escapeType(PO, State);
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Call resolution
// ---------------------------------------------------------------------------

void intersectFuncSets(FuncSet &FS1, FuncSet &FS2, FuncSet &FS) {
  FS.clear();
  for (auto *F : FS1) {
    if (FS2.count(F))
      FS.insert(F);
  }
}

bool getTargetsWithLayerType(size_t TyHash, int Idx, FuncSet &FS,
                             AnalysisState &State) {
  if (Idx == -1) {
    for (auto &FSet : State.TypeIdxFuncsMap[TyHash])
      FS.insert(FSet.second.begin(), FSet.second.end());
  } else {
    FS = State.TypeIdxFuncsMap[TyHash][Idx];
    FS.insert(State.TypeIdxFuncsMap[TyHash][-1].begin(),
              State.TypeIdxFuncsMap[TyHash][-1].end());
  }
  return true;
}

bool getDependentTypes(Type *Ty, int Idx, std::set<HashIntPair> &PropSet,
                       AnalysisState &State) {
  std::list<HashIntPair> LT;
  LT.push_back(hashidx_c(typeHash(Ty, State), Idx));
  std::set<HashIntPair> Visited;

  while (!LT.empty()) {
    HashIntPair TI = LT.front();
    LT.pop_front();
    if (!Visited.insert(TI).second)
      continue;

    for (auto &Prop : State.TypeIdxPropMap[TI.first][TI.second]) {
      PropSet.insert(Prop);
      LT.push_back(Prop);
    }
    for (auto &Prop : State.TypeIdxPropMap[TI.first][-1]) {
      PropSet.insert(Prop);
      LT.push_back(Prop);
    }
  }
  return true;
}

void findCalleesWithType(CallInst *CI, FuncSet &S, AnalysisState &State) {
  if (CI->isInlineAsm())
    return;

  size_t CIH = callHash(CI);
  for (Function *F : State.AddressTakenFuncs) {
    if (F->isIntrinsic())
      continue;

    CallBase *CB = dyn_cast<CallBase>(CI);
    if (F->getFunctionType()->isVarArg()) {
      // Compare only known args.
    } else if (F->arg_size() != CB->arg_size()) {
      continue;
    }

    if (callHash(CI) == funcHash(F)) {
      S.insert(F);
      continue;
    }

    Module *CalleeM = F->getParent();
    Module *CallerM = CI->getFunction()->getParent();

    bool Matched = true;
    User::op_iterator AI = CB->arg_begin();
    for (Function::arg_iterator FI = F->arg_begin(), FE = F->arg_end();
         FI != FE; ++FI, ++AI) {
      if (!fuzzyTypeMatch(FI->getType(), (*AI)->getType(), CalleeM, CallerM,
                          State)) {
        Matched = false;
        break;
      }
    }

    if (Matched) {
      if (!fuzzyTypeMatch(F->getReturnType(), CI->getType(), CalleeM, CallerM,
                          State))
        Matched = false;
    }

    if (Matched)
      S.insert(F);
  }
}

bool findCalleesWithMLTA(CallInst *CI, FuncSet &FS, AnalysisState &State) {
  // First layer: signature match.
  FS = State.SigFuncsMap[callHash(CI)];
  if (FS.empty())
    return false;

  FuncSet FS1, FS2;
  Type *PrevLayerTy = dyn_cast<CallBase>(CI)->getFunctionType();
  Value *CV = CI->getCalledOperand();
  Value *NextV = nullptr;
  int LayerNo = 1;

  bool ContinueNextLayer = true;
  while (ContinueNextLayer) {
    if (LayerNo >= static_cast<int>(MAX_TYPE_LAYER))
      break;

    if (State.TypeCapSet.count(typeHash(PrevLayerTy, State)))
      break;

    std::set<Value *> Visited;
    std::list<TypeIntPair> TyList;
    nextLayerBaseType(CV, TyList, NextV, State);
    if (TyList.empty())
      break;

    for (auto &TI : TyList) {
      if (LayerNo >= static_cast<int>(MAX_TYPE_LAYER))
        break;
      ++LayerNo;

      size_t TyIdxHash = typeIdxHash(TI.first, TI.second, State);
      size_t TyIdxHash_1 = typeIdxHash(TI.first, -1, State);

      // Check escape set
      if (State.TypeEscapeSet.count(TyIdxHash) ||
          State.TypeEscapeSet.count(TyIdxHash_1))
        break;

      getTargetsWithLayerType(typeHash(TI.first, State), TI.second, FS1,
                              State);

      // Collect from dependent propagated types
      std::set<HashIntPair> PropSet;
      getDependentTypes(TI.first, TI.second, PropSet, State);
      for (auto &Prop : PropSet) {
        getTargetsWithLayerType(Prop.first, Prop.second, FS2, State);
        FS1.insert(FS2.begin(), FS2.end());
      }

      // Intersect to narrow candidates
      intersectFuncSets(FS1, FS, FS2);
      FS = FS2;

      CV = NextV;

      if (State.TypeCapSet.count(typeHash(TI.first, State))) {
        ContinueNextLayer = false;
        break;
      }

      PrevLayerTy = TI.first;
    }
    TyList.clear();
  }

  return true;
}

FuncSet resolveIndirectCall(CallBase *CB, AnalysisState &State) {
  if (State.HasOpaquePointers) {
    // MLTA type analysis requires typed pointers. Fall back to signature
    // matching for opaque-pointer IR.
    FuncSet Result;
    size_t CH = callHash(CB);
    auto It = State.SigFuncsMap.find(CH);
    if (It != State.SigFuncsMap.end())
      Result = It->second;
    if (Result.size() > MAX_ICALLEE_TARGETS)
      Result.clear();
    return Result;
  }

  FuncSet Result;

  // Start with signature-matched functions.
  size_t CH = callHash(CB);
  auto It = State.SigFuncsMap.find(CH);
  if (It == State.SigFuncsMap.end() || It->second.empty())
    return Result;

  // Use MLTA for multi-layer type refinement.
  if (auto *CI = dyn_cast<CallInst>(CB)) {
    FuncSet FS = It->second;
    findCalleesWithMLTA(CI, FS, State);
    Result = std::move(FS);
  } else {
    Result = It->second;
  }

  // Cap targets to avoid state explosion.
  if (Result.size() > MAX_ICALLEE_TARGETS)
    Result.clear();

  return Result;
}

// ---------------------------------------------------------------------------
// Phase 2 main entry: buildMLTAData
// ---------------------------------------------------------------------------

void buildMLTAData(AnalysisState &State) {
  // Step A: Load struct element name map for anonymous struct matching.
  if (!State.HasOpaquePointers)
    loadElementsStructNameMap(State);

  // Step B: Collect address-taken functions and populate sigFuncsMap.
  // Note: funcHash uses Type::print which works with opaque pointers.
  for (const auto &ModulePtr : State.Modules) {
    for (Function &F : *ModulePtr) {
      if (F.hasAddressTaken()) {
        State.AddressTakenFuncs.insert(&F);
        State.SigFuncsMap[funcHash(&F, false)].insert(&F);
      }
      if (!F.isDeclaration() && F.hasExternalLinkage())
        State.GlobalFuncMap[F.getGUID()] = &F;
    }
  }

  // Step C: Replace declarations with definitions in SigFuncsMap.
  for (auto &SF : State.SigFuncsMap) {
    llvm::SmallVector<llvm::Function *, 4> ToErase;
    llvm::SmallVector<llvm::Function *, 4> ToInsert;
    for (Function *F : SF.second) {
      if (F->isDeclaration()) {
        ToErase.push_back(F);
        auto DefIt = State.GlobalFuncMap.find(F->getGUID());
        if (DefIt != State.GlobalFuncMap.end())
          ToInsert.push_back(DefIt->second);
      }
    }
    for (Function *F : ToErase)
      SF.second.erase(F);
    for (Function *F : ToInsert)
      SF.second.insert(F);
  }

  // Steps D-F: Type confinement and propagation require typed pointers.
  if (State.HasOpaquePointers)
    return;

  // Step D: Type confinement on global initializers.
  for (const auto &ModulePtr : State.Modules) {
    for (GlobalVariable &GV : ModulePtr->globals()) {
      if (GV.hasInitializer()) {
        Type *ITy = GV.getInitializer()->getType();
        if (!ITy->isPointerTy() && !isCompositeType(ITy))
          continue;
        typeConfineInInitializer(&GV, State);
      }
    }
  }

  // Step E: Type confinement and propagation in function bodies.
  for (const auto &ModulePtr : State.Modules) {
    for (Function &F : *ModulePtr) {
      if (F.isDeclaration())
        continue;
      typeConfineInFunction(&F, State);
      typePropInFunction(&F, State);
    }
  }

  // Step F: Replace declarations in TypeIdxFuncsMap.
  for (auto &TF : State.TypeIdxFuncsMap) {
    for (auto &IF : TF.second) {
      llvm::SmallVector<llvm::Function *, 4> ToErase;
      llvm::SmallVector<llvm::Function *, 4> ToInsert;
      for (Function *F : IF.second) {
        if (F->isDeclaration()) {
          ToErase.push_back(F);
          auto DefIt = State.GlobalFuncMap.find(F->getGUID());
          if (DefIt != State.GlobalFuncMap.end())
            ToInsert.push_back(DefIt->second);
        }
      }
      for (Function *F : ToErase)
        IF.second.erase(F);
      for (Function *F : ToInsert)
        IF.second.insert(F);
    }
  }
}

} // namespace mallocchecker
