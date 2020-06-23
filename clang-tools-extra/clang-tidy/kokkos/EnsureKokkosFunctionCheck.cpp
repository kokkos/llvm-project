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

using namespace clang;
AST_MATCHER_P(Decl, matchesAttr, std::string, RegExp) {
  assert(!RegExp.empty());
  llvm::Regex Re(RegExp);
  for (auto const *Attr : Node.attrs()) {
    if (auto const *Anna = dyn_cast<AnnotateAttr>(Attr)) {
      if (Re.match(Anna->getAnnotation())) {
        return true;
      }
    }
  }
  return false;
}

std::string KF_Regex = "KOKKOS_.*FUNCTION";

auto notKFunc = functionDecl(unless(matchesAttr(KF_Regex)),
                             unless(isExpansionInSystemHeader()));
auto notKCalls = callExpr(callee(notKFunc)).bind("CE");

CallExpr const *checkLambdaBody(CXXRecordDecl const *Lambda) {
  assert(Lambda->isLambda());

  if (auto const *FD = Lambda->getLambdaCallOperator()) {
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

void EnsureKokkosFunctionCheck::registerMatchers(MatchFinder *Finder) {

  std::string KF_Regex = "KOKKOS_.*FUNCTION";

  auto notKFunc = functionDecl(unless(matchesAttr(KF_Regex)),
                               unless(isExpansionInSystemHeader()));
  auto notKCalls = callExpr(callee(notKFunc)).bind("CE");

  Finder->addMatcher(
      functionDecl(matchesAttr(KF_Regex), forEachDescendant(notKCalls))
          .bind("ParentFD"),
      this);

  auto Lambda = expr(hasType(cxxRecordDecl(isLambda()).bind("Lambda")));
  Finder->addMatcher(callExpr(isKokkosParallelCall(), hasAnyArgument(Lambda)),
                     this);
}

void EnsureKokkosFunctionCheck::check(const MatchFinder::MatchResult &Result) {

  auto const *ParentFD = Result.Nodes.getNodeAs<FunctionDecl>("ParentFD");
  auto const *CE = Result.Nodes.getNodeAs<CallExpr>("CE");
  auto const *Lambda = Result.Nodes.getNodeAs<CXXRecordDecl>("Lambda");

  if (ParentFD != nullptr) {
    diag(CE->getDirectCallee()->getLocation(),
         "function %0 is missing a KOKKOS_X_FUNCTION annotation")
        << CE->getDirectCallee();
    diag(CE->getBeginLoc(), "Called here in function %0.", DiagnosticIDs::Note)
        << ParentFD;
  }
  if (Lambda != nullptr) {
    auto BadCall = checkLambdaBody(Lambda);
    if (BadCall) {
      diag(BadCall->getBeginLoc(), "Function %0 called in a lambda was missing "
                                   "KOKKOS_X_FUNCTION annotation.")
          << BadCall->getDirectCallee();
      diag(Lambda->getLocation(), "Lambda is here", DiagnosticIDs::Note);
    }
  }
}

} // namespace kokkos
} // namespace tidy
} // namespace clang
