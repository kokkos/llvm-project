//===--- KokkosMatchers.h - clang-tidy ------------------------===//
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

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_KOKKOSMATCHERS_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_KOKKOSMATCHERS_H

#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include <string>

namespace clang {
namespace tidy {
namespace kokkos {

AST_MATCHER_FUNCTION(ast_matchers::internal::Matcher<FunctionDecl>,
                     kokkosParallelXFunctionDecl) {
  using namespace clang::ast_matchers;
  return functionDecl(matchesName("::Kokkos::parallel_.*"));
}

AST_MATCHER(CallExpr, isKokkosParallelCall) {
  using namespace clang::ast_matchers;
  if (auto const *FD = Node.getDirectCallee()) {
    std::string Name = FD->getQualifiedNameAsString();
    StringRef SR(Name);
    if (SR.startswith("Kokkos::parallel_") ||
        SR.startswith("::Kokkos::parallel_")) {
      return true;
    }
  }

  return false;
}

AST_MATCHER_P(Decl, matchesAttr, std::string, RegExp) {
  using namespace clang::ast_matchers;
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

bool explicitlyUsingHostExecutionSpace(CallExpr const *CE,
                                       std::string const &RegexString);

} // namespace kokkos
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_KOKKOSMATCHERS_H
