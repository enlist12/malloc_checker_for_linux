#ifndef INDIRECT_CALL_RESOLVER_H
#define INDIRECT_CALL_RESOLVER_H

#include "MallocCheckerAnalyzer.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <list>
#include <map>
#include <set>
#include <utility>
#include <vector>

namespace llvm {
class Type;
class Value;
class GlobalVariable;
class GEPOperator;
} // namespace llvm

namespace mallocchecker {

using FuncSet = llvm::SmallPtrSet<llvm::Function *, 8>;
using TypeIntPair = std::pair<llvm::Type *, int>;
using HashIntPair = std::pair<size_t, int>;

struct StructFieldInfo {
  const llvm::Value *StoredValue = nullptr;
  const llvm::Function *Context = nullptr;
};

struct StructFieldKey {
  const llvm::Value *BasePtr = nullptr;
  llvm::SmallVector<int, 4> Indices;

  bool operator==(const StructFieldKey &Other) const {
    return BasePtr == Other.BasePtr && Indices == Other.Indices;
  }
};

struct StructFieldKeyHash {
  size_t operator()(const StructFieldKey &K) const {
    size_t H = reinterpret_cast<uintptr_t>(K.BasePtr);
    for (int Idx : K.Indices)
      H ^= static_cast<size_t>(Idx) + 0x9e3779b9 + (H << 6) + (H >> 2);
    return H;
  }
};

bool isCompositeType(llvm::Type *Ty);
llvm::Type *getFuncPtrType(llvm::Value *V);
llvm::Function *getBaseFunction(llvm::Value *V);

size_t funcHash(llvm::Function *F, bool WithName = false);
size_t callHash(llvm::CallBase *CB);
size_t typeHash(llvm::Type *Ty, AnalysisState &State);
size_t typeIdxHash(llvm::Type *Ty, int Idx, AnalysisState &State);
size_t hashIdxHash(size_t Hs, int Idx);
void structTypeHash(llvm::StructType *STy, std::set<size_t> &HSet,
                    AnalysisState &State);

TypeIntPair typeidx_c(llvm::Type *Ty, int Idx);
HashIntPair hashidx_c(size_t Hash, int Idx);

bool fuzzyTypeMatch(llvm::Type *Ty1, llvm::Type *Ty2, llvm::Module *M1,
                    llvm::Module *M2, AnalysisState &State);

void loadElementsStructNameMap(AnalysisState &State);

// Type traversal
llvm::Type *getBaseType(llvm::Value *V, std::set<llvm::Value *> &Visited,
                        AnalysisState &State);
bool nextLayerBaseType(llvm::Value *V, std::list<TypeIntPair> &TyList,
                       llvm::Value *&NextV, std::set<llvm::Value *> &Visited,
                       AnalysisState &State);
bool getBaseTypeChain(std::list<TypeIntPair> &Chain, llvm::Value *V,
                      bool &Complete, AnalysisState &State);
bool getGEPLayerTypes(llvm::GEPOperator *GEP,
                      std::list<TypeIntPair> &TyList, AnalysisState &State);

// Type confinement
void confineTargetFunction(llvm::Value *V, llvm::Function *F,
                           AnalysisState &State);
bool typeConfineInInitializer(llvm::GlobalVariable *GV, AnalysisState &State);
bool typeConfineInFunction(llvm::Function *F, AnalysisState &State);

// Type propagation
bool typePropInFunction(llvm::Function *F, AnalysisState &State);
void propagateType(llvm::Value *ToV, llvm::Type *FromTy, int Idx,
                   AnalysisState &State);
inline void propagateType(llvm::Value *ToV, llvm::Type *FromTy,
                          AnalysisState &State) {
  propagateType(ToV, FromTy, 0, State);
}
void escapeType(llvm::Value *V, AnalysisState &State);
void intersectFuncSets(FuncSet &FS1, FuncSet &FS2, FuncSet &FS);
bool getTargetsWithLayerType(size_t TyHash, int Idx, FuncSet &FS,
                             AnalysisState &State);
bool getDependentTypes(llvm::Type *Ty, int Idx,
                       std::set<HashIntPair> &PropSet,
                       AnalysisState &State);

// Resolution APIs
void findCalleesWithType(llvm::CallInst *CI, FuncSet &S, AnalysisState &State);
bool findCalleesWithMLTA(llvm::CallInst *CI, FuncSet &FS,
                         AnalysisState &State);
FuncSet resolveIndirectCall(llvm::CallBase *CB, AnalysisState &State);

// Main entry point (Phase 2)
void buildMLTAData(AnalysisState &State);

} // namespace mallocchecker

#endif
