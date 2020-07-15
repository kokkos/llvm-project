//===--- ImplicitThisCaptureCheck.cpp - clang-tidy ------------------------===//
//
// Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC
// (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S.
// Government retains certain rights in this software.
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ImplicitThisCaptureCheck.h"
#include "KokkosMatchers.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/ADT/Optional.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace kokkos {

namespace {
llvm::Optional<SourceLocation> capturesThis(CXXRecordDecl const *CRD) {
  if (!CRD->isLambda()) {
    return llvm::None;
  }

  for (auto const &Capture : CRD->captures()) {
    if (Capture.capturesThis()) {
      return llvm::Optional<SourceLocation>(Capture.getLocation());
    }
  }

  return llvm::None;
}

} // namespace

ImplicitThisCaptureCheck::ImplicitThisCaptureCheck(StringRef Name,
                                                   ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context) {
  AllowIfExplicitHost = std::stoi(Options.get("AllowIfExplicitHost", "0"));
}

void ImplicitThisCaptureCheck::storeOptions(
    ClangTidyOptions::OptionMap &Opts) {
  Options.store(Opts, "AllowIfExplicitHost",
                std::to_string(AllowIfExplicitHost));
}

void ImplicitThisCaptureCheck::registerMatchers(MatchFinder *Finder) {
  auto isAllowedPolicy = expr(hasType(
      cxxRecordDecl(matchesName("::Impl::ThreadVectorRangeBoundariesStruct.*|"
                                "::Impl::TeamThreadRangeBoundariesStruct.*"))));

  auto Lambda = expr(hasType(cxxRecordDecl(isLambda()).bind("Lambda")));

  Finder->addMatcher(callExpr(isKokkosParallelCall(), hasAnyArgument(Lambda),
                              unless(hasAnyArgument(isAllowedPolicy)))
                         .bind("x"),
                     this);
}

void ImplicitThisCaptureCheck::check(const MatchFinder::MatchResult &Result) {
  auto const *CE = Result.Nodes.getNodeAs<CallExpr>("x");

  if (AllowIfExplicitHost != 0) {
    if (explicitlyDefaultHostExecutionSpace(CE)) {
      return;
    }
  }

  auto const *Lambda = Result.Nodes.getNodeAs<CXXRecordDecl>("Lambda");
  auto CaptureLocation = capturesThis(Lambda);
  if (CaptureLocation) {
    diag(Lambda->getBeginLoc(), "Lambda passed to %0 implicitly captures this.")
        << CE->getDirectCallee()->getName();
    diag(CaptureLocation.getValue(), "the captured variable is used here.",
         DiagnosticIDs::Note);
  }
}

} // namespace kokkos
} // namespace tidy
} // namespace clang
