//===--- ImplicitThisCaptureCheck.h - clang-tidy ----------------*- C++ -*-===//
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

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_IMPLICITTHISCAPTURECHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_IMPLICITTHISCAPTURECHECK_H

#include "../ClangTidyCheck.h"

#include <string>

namespace clang {
namespace tidy {
namespace kokkos {

/// Check to detect when a lambda passed to a ::Kokkos::parallel_* implicitly
/// captures the this pointer
class ImplicitThisCaptureCheck : public ClangTidyCheck {
public:
  ImplicitThisCaptureCheck(StringRef Name, ClangTidyContext *Context);
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void storeOptions(ClangTidyOptions::OptionMap &Opts) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
private:
  int AllowIfExplicitHost;
};

} // namespace kokkos
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_KOKKOS_IMPLICITTHISCAPTURECHECK_H
