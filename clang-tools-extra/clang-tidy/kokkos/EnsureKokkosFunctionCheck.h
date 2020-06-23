//===--- EnsureKokkosFunctionCheck.h - clang-tidy ---------------*- C++ -*-===//
//
// Copyright 2020 National Technology & Engineering Solutions of Sandia,
// LLC (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S.
// Government retains certain rights in this software.
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_ENSUREKOKKOSFUNCTIONCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_ENSUREKOKKOSFUNCTIONCHECK_H

#include "../ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace kokkos {

/// Check that ensures user provided functions were properly annotated
class EnsureKokkosFunctionCheck : public ClangTidyCheck {
public:
  EnsureKokkosFunctionCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace kokkos
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_ENSUREKOKKOSFUNCTIONCHECK_H
