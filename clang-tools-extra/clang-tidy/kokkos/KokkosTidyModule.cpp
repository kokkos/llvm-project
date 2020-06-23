//===--- KokkosTidyModule.cpp - clang-tidy ----------------------------------===//
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

#include "../ClangTidy.h"
#include "../ClangTidyModule.h"
#include "../ClangTidyModuleRegistry.h"
#include "EnsureKokkosFunctionCheck.h"
#include "ImplicitThisCaptureCheck.h"

namespace clang {
namespace tidy {
namespace kokkos {

class KokkosModule : public ClangTidyModule {
public:
  void addCheckFactories(ClangTidyCheckFactories &CheckFactories) override {
    CheckFactories.registerCheck<EnsureKokkosFunctionCheck>(
        "kokkos-ensure-kokkos-function");
    CheckFactories.registerCheck<ImplicitThisCaptureCheck>(
        "kokkos-implicit-this-capture");
  }
};

} // namespace kokkos

// Register the DarwinTidyModule using this statically initialized variable.
static ClangTidyModuleRegistry::Add<kokkos::KokkosModule>
    X("kokkos-module", "Adds Kokkos specific linting checks.");

// This anchor is used to force the linker to link in the generated object file
// and thus register the KokkosModule.
volatile int KokkosModuleAnchorSource = 0;

} // namespace tidy
} // namespace clang
