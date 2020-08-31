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

namespace {
TypedefNameDecl const *getTypedefFromFirstTemplateArg(Expr const *E) {
  if (E == nullptr) {
    return nullptr;
  }

  auto const *TST = E->getType()->getAs<TemplateSpecializationType>();
  if (TST == nullptr) {
    return nullptr;
  }
  if (TST->getNumArgs() < 1) {
    return nullptr;
  }

  auto const *TDT = TST->getArg(0).getAsType()->getAs<TypedefType>();
  if (TDT == nullptr) {
    return nullptr;
  }

  auto const *TDD = dyn_cast_or_null<TypedefNameDecl>(TDT->getDecl());
  return TDD;
}
} // namespace

bool matchesAnnotation(Decl const *D, std::string const &RegExp) {
  assert(!RegExp.empty());
  llvm::Regex Re(RegExp);
  for (auto const *Attr : D->attrs()) {
    if (auto const *Anna = dyn_cast<AnnotateAttr>(Attr)) {
      if (Re.match(Anna->getAnnotation())) {
        return true;
      }
    }
  }
  return false;
}


bool explicitlyDefaultHostExecutionSpace(CallExpr const *CE) {
  using namespace clang::ast_matchers;
  auto &Ctx = CE->getCalleeDecl()->getASTContext();

  // We will assume that any policy where the user might explicitly ask for the
  // host space inherits from Impl::PolicyTraits
  auto FilterArgs = hasAnyArgument(
      expr(hasType(classTemplateSpecializationDecl(isDerivedFrom(
               cxxRecordDecl(matchesName("Impl::PolicyTraits"))))))
          .bind("expr"));

  // We have to jump through some hoops to find this, if we just looked at the
  // template type of the Policy constructor we lose the sugar and instead of
  // Kokkos::DefaultHostExecutionSpace we get what the ever the typedef was set
  // to such as Kokkos::Serial, preventing us from figuring out if the user
  // actually asked for a host space specifically or just happens to have a
  // host space as the default space.
  auto BNs = match(callExpr(FilterArgs), *CE, Ctx);
  for (auto &BN : BNs) {
    if (auto const *TDD =
            getTypedefFromFirstTemplateArg(BN.getNodeAs<Expr>("expr"))) {
      return matchesAnnotation(TDD, "DefaultHostExecutionSpace");
    }
  }

  return false;
}

} // namespace kokkos
} // namespace tidy
} // namespace clang
