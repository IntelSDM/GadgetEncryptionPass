#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct GadgetEncryptionPass : llvm::PassInfoMixin<GadgetEncryptionPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunGadgetEncryption(llvm::Module& m);

extern llvm::cl::opt<bool> GadgetEncryptionEnable;