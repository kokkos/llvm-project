//===- unittests/StaticAnalyzer/ParamRegionTest.cpp -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Reusables.h"

#include "clang/Tooling/Tooling.h"
#include "gtest/gtest.h"

namespace clang {
namespace ento {
namespace {

class ParamRegionTestConsumer : public ExprEngineConsumer {
  void checkForSameParamRegions(MemRegionManager &MRMgr,
                                const StackFrameContext *SFC,
                                const ParmVarDecl *PVD) {
    for (const auto *D2: PVD->redecls()) {
      const auto *PVD2 = cast<ParmVarDecl>(D2);
      assert(MRMgr.getVarRegion(PVD, SFC) == MRMgr.getVarRegion(PVD2, SFC));
    }
  }

  void performTest(const Decl *D) {
    StoreManager &StMgr = Eng.getStoreManager();
    MemRegionManager &MRMgr = StMgr.getRegionManager();
    const StackFrameContext *SFC =
        Eng.getAnalysisDeclContextManager().getStackFrame(D);

    if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
      for (const auto *P : FD->parameters()) {
        const TypedValueRegion *Reg = MRMgr.getVarRegion(P, SFC);
        if (SFC->inTopFrame())
          assert(isa<NonParamVarRegion>(Reg));
        else
          assert(isa<ParamVarRegion>(Reg));
        checkForSameParamRegions(MRMgr, SFC, P);
      }
    } else if (const auto *CD = dyn_cast<CXXConstructorDecl>(D)) {
      for (const auto *P : CD->parameters()) {
        const TypedValueRegion *Reg = MRMgr.getVarRegion(P, SFC);
        if (SFC->inTopFrame())
          assert(isa<NonParamVarRegion>(Reg));
        else
          assert(isa<ParamVarRegion>(Reg));
        checkForSameParamRegions(MRMgr, SFC, P);
      }
    } else if (const auto *MD = dyn_cast<ObjCMethodDecl>(D)) {
      for (const auto *P : MD->parameters()) {
        const TypedValueRegion *Reg = MRMgr.getVarRegion(P, SFC);
        if (SFC->inTopFrame())
          assert(isa<NonParamVarRegion>(Reg));
        else
          assert(isa<ParamVarRegion>(Reg));
        checkForSameParamRegions(MRMgr, SFC, P);
      }
    }
  }

public:
  ParamRegionTestConsumer(CompilerInstance &C) : ExprEngineConsumer(C) {}

  bool HandleTopLevelDecl(DeclGroupRef DG) override {
    for (const auto *D : DG) {
      performTest(D);
    }
    return true;
  }
};

class ParamRegionTestAction : public ASTFrontendAction {
public:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &Compiler,
                                                 StringRef File) override {
    return std::make_unique<ParamRegionTestConsumer>(Compiler);
  }
};

TEST(ParamRegion, ParamRegionTest) {
  EXPECT_TRUE(
      tooling::runToolOnCode(std::make_unique<ParamRegionTestAction>(),
                             R"(void foo(int n);
                                void baz(int p);

                                void foo(int n) {
                                  auto lambda = [n](int m) {
                                    return n + m;
                                  };

                                  int k = lambda(2);
                                }

                                void bar(int l) {
                                  foo(l);
                                }

                                struct S {
                                  int n;
                                  S(int nn): n(nn) {}
                                };

                                void baz(int p) {
                                  S s(p);
                                }

                                void bar(int l);
                                void baz(int p);)"));
  EXPECT_TRUE(
      tooling::runToolOnCode(std::make_unique<ParamRegionTestAction>(),
                             R"(@interface O
                                + alloc;
                                - initWithInt:(int)q;
                                @end

                                void qix(int r) {
                                  O *o = [[O alloc] initWithInt:r];
                                })",
                             "input.m"));
}

} // namespace
} // namespace ento
} // namespace clang
