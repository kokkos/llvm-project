//===--- EnsureKokkosFunctionCheck.cpp - clang-tidy -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "EnsureKokkosFunctionCheck.h"
#include "KokkosMatchers.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace {

std::string KF_Regex = "KOKKOS_.*FUNCTION";

CallExpr const *checkLambdaBody(CXXRecordDecl const *Lambda,
                                std::string const &AllowedFuncRegex) {
  assert(Lambda->isLambda());

  if (auto const *FD = Lambda->getLambdaCallOperator()) {
    auto AllowedFuncMatch = [AFR = AllowedFuncRegex] {
      if (AFR.empty()) {
        return unless(matchesName("a^")); // Never match anything
      }
      return unless(matchesName(AFR));
    }();
    auto notKFunc =
        functionDecl(unless(matchesAttr(KF_Regex)),
                     unless(isExpansionInSystemHeader()), AllowedFuncMatch);

    auto notKCalls = callExpr(callee(notKFunc)).bind("CE");

    auto BadCalls = match(functionDecl(forEachDescendant(notKCalls)), *FD,
                          FD->getASTContext());

    if (!BadCalls.empty()) {
      return selectFirst<CallExpr>("CE", BadCalls);
    }
  }

  return nullptr;
}

} // namespace

namespace clang {
namespace tidy {
namespace kokkos {

EnsureKokkosFunctionCheck::EnsureKokkosFunctionCheck(StringRef Name,
                                                     ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context) {
  CheckIfExplicitHost = std::stoi(Options.get("CheckIfExplicitHost", "0"));
  AllowedFunctionsRegex = Options.get("AllowedFunctionsRegex", "");
}

void EnsureKokkosFunctionCheck::storeOptions(
    ClangTidyOptions::OptionMap &Opts) {
  Options.store(Opts, "AllowedFunctionsRegex", AllowedFunctionsRegex);
  Options.store(Opts, "CheckIfExplicitHost",
                std::to_string(CheckIfExplicitHost));
}

void EnsureKokkosFunctionCheck::registerMatchers(MatchFinder *Finder) {
  auto AllowedFuncMatch = [AFR = AllowedFunctionsRegex] {
    if (AFR.empty()) {
      return unless(matchesName("a^")); // Never match anything
    }
    return unless(matchesName(AFR));
  }();

  auto notKFunc =
      functionDecl(unless(matchesAttr(KF_Regex)),
                   unless(isExpansionInSystemHeader()), AllowedFuncMatch);

  auto notKCalls = callExpr(callee(notKFunc)).bind("CE");

  // We have to be sure that we don't match functionDecls in systems headers,
  // because they might call our Functor, which if it is a lambda will not be
  // marked with KOKKOS_FUNCITON
  Finder->addMatcher(functionDecl(matchesAttr(KF_Regex),
                                  unless(isExpansionInSystemHeader()),
                                  forEachDescendant(notKCalls))
                         .bind("ParentFD"),
                     this);

  auto Lambda = expr(hasType(cxxRecordDecl(isLambda()).bind("Lambda")));
  Finder->addMatcher(
      callExpr(isKokkosParallelCall(), hasAnyArgument(Lambda)).bind("KokkosCE"),
      this);
}

void EnsureKokkosFunctionCheck::check(const MatchFinder::MatchResult &Result) {

  auto const *ParentFD = Result.Nodes.getNodeAs<FunctionDecl>("ParentFD");
  auto const *CE = Result.Nodes.getNodeAs<CallExpr>("CE");
  auto const *Lambda = Result.Nodes.getNodeAs<CXXRecordDecl>("Lambda");

  if (ParentFD != nullptr) {
    diag(CE->getBeginLoc(),
         "function %0 called in %1 is missing a KOKKOS_X_FUNCTION annotation")
        << CE->getDirectCallee() << ParentFD;
    diag(CE->getDirectCallee()->getLocation(), "Function %0 declared here",
         DiagnosticIDs::Note)
        << CE->getDirectCallee();
  }
  if (Lambda != nullptr) {
    auto const* CE = Result.Nodes.getNodeAs<CallExpr>("KokkosCE");
    if(explicitlyUsingHostExecutionSpace(CE, "Hi")){
    }
    auto const *BadCall = checkLambdaBody(Lambda, AllowedFunctionsRegex);
    if (BadCall) {
      diag(BadCall->getBeginLoc(), "Function %0 called in a lambda was missing "
                                   "KOKKOS_X_FUNCTION annotation.")
          << BadCall->getDirectCallee();
    }
  }
}

} // namespace kokkos
} // namespace tidy
} // namespace clang
