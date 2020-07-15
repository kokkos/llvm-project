//===--- KokkosMatchers.cpp - clang-tidy ------------------------===//
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

#include "KokkosMatchers.h"

namespace clang {
namespace tidy {
namespace kokkos {

bool explicitlyUsingHostExecutionSpace(CallExpr const *CE,
                                       std::string const &RegexString) {
  using namespace clang::ast_matchers;
  auto &Ctx = CE->getCalleeDecl()->getASTContext();

  // We will assume that any policy where the user might explicitly ask for the
  // host space inherits from Impl::PolicyTraits
  auto FilterArgs =
      hasAnyArgument(expr(hasType(classTemplateSpecializationDecl(
                                      isDerivedFrom(cxxRecordDecl(
                                          matchesName("Impl::PolicyTraits"))))
                                      .bind("Policy")))
                         .bind("expr"));

  // We have to jump through some hoops to find this, if we just looked at the
  // template type of the Policy constructor we lose the sugar and instead of
  // Kokkos::DefaultHostExecutionSpace we get what the ever the typedef was set
  // to such as Kokkos::Serial, preventing us from figuring out if the user
  // actually asked for a host space specifically or just happens to have a
  // host space as the default space.
  llvm::Regex Reg(RegexString);
  auto BNs = match(callExpr(FilterArgs), *CE, Ctx);
  for (auto &BN : BNs) {
    if (auto const *E = BN.getNodeAs<Expr>("expr")) {
      if (auto const *TST = E->getType()->getAs<TemplateSpecializationType>()) {
        for (auto const &TA : TST->template_arguments()) {
          if (auto const *TDT = TA.getAsType()->getAs<TypedefType>()) {
            if (auto const *TDD = TDT->getDecl()) {
              for (auto const *Attr : TDD->attrs()) {
                if (auto const *Anna = dyn_cast<AnnotateAttr>(Attr)) {
                  if (Anna->getAnnotation().equals(
                          "DefaultHostExecutionSpace")) {
                    return true;
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return false;
}

} // namespace kokkos
} // namespace tidy
} // namespace clang
