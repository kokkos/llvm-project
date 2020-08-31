//===--- EnsureKokkosFunctionCheck.cpp - clang-tidy -----------------------===//
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

#include "EnsureKokkosFunctionCheck.h"
#include "KokkosMatchers.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace kokkos {
namespace {

std::string KF_Regex = "KOKKOS_.*FUNCTION"; // NOLINT

auto notKFunc(std::string const &AllowedFuncRegex) {
  auto AllowedFuncMatch = unless(matchesName(AllowedFuncRegex));
  return functionDecl(unless(matchesAttr(KF_Regex)),
                      unless(isExpansionInSystemHeader()), AllowedFuncMatch);
}

bool isAnnotated(CXXMethodDecl const *Method) {
  // If the method is annotated the match will not be empty
  return !match(cxxMethodDecl(matchesAttr(KF_Regex)), *Method,
                Method->getASTContext())
              .empty();
}

// TODO one day we might want to check if the lambda is local to our current
// function context, but until someone complains that's a lot of work. The
// other case we aren't going to deal with is: void foo(){ struct S { static
// void func(){} }; S::func(); }
bool callExprIsToLambaOp(CallExpr const *CE) {
  if (auto const *CMD =
          dyn_cast_or_null<CXXMethodDecl>(CE->getDirectCallee())) {
    if (auto const *Parent = CMD->getParent()) {
      if (Parent->isLambda()) {
        return true;
      }
    }
  }
  return false;
}

auto checkLambdaBody(CXXRecordDecl const *Lambda,
                     std::string const &AllowedFuncRegex) {
  assert(Lambda->isLambda());
  llvm::SmallPtrSet<CallExpr const *, 1> BadCallSet;
  auto const *FD = Lambda->getLambdaCallOperator();
  if (!FD) {
    return BadCallSet;
  }

  auto notKCalls = // NOLINT
      callExpr(callee(notKFunc(AllowedFuncRegex))).bind("CE");

  auto BadCalls = match(functionDecl(forEachDescendant(notKCalls)), *FD,
                        FD->getASTContext());

  for (auto BadCall : BadCalls) {
    auto const *CE = BadCall.getNodeAs<CallExpr>("CE");
    if (callExprIsToLambaOp(CE)) { // function call handles nullptr
      continue;
    }

    BadCallSet.insert(CE);
  }

  return BadCallSet;
}

// Recurses through the tree of all calls to functions with visble bodies
void recurseCallExpr(
    llvm::SmallPtrSet<CXXMethodDecl const *, 8> const &FunctorMethods,
    CallExpr const *Call,
    llvm::SmallPtrSet<CXXMethodDecl const *, 4> &Results) {

  // Get the body of the called function
  auto const *CallDecl = Call->getCalleeDecl();
  if (CallDecl == nullptr || !CallDecl->hasBody()) {
    return;
  }

  auto &ASTContext = CallDecl->getASTContext();

  // Check if the called function is a member function of the functor
  // if yes then write the result back out.
  if (auto const *Method = dyn_cast<CXXMethodDecl>(CallDecl)) {
    if (FunctorMethods.count(Method) > 0) {
      Results.insert(Method);
    }
  }

  // Match all callexprs in our body
  auto CEs = match(compoundStmt(forEachDescendant(callExpr().bind("CE"))),
                   *(CallDecl->getBody()), ASTContext);

  // Check all those calls for uses of members of the functor as well
  for (auto BN : CEs) {
    if (auto const *CE = BN.getNodeAs<CallExpr>("CE")) {
      recurseCallExpr(FunctorMethods, CE, Results);
    }
  }
}

// Find methods from our functor called in the tree of Kokkos::parallel_x
auto checkFunctorBody(CXXRecordDecl const *Functor, CallExpr const *CallSite) {
  llvm::SmallPtrSet<CXXMethodDecl const *, 8> FunctorMethods;
  for (auto const *Method : Functor->methods()) {
    FunctorMethods.insert(Method);
  }
  llvm::SmallPtrSet<CXXMethodDecl const *, 4> Results;
  recurseCallExpr(FunctorMethods, CallSite, Results);

  return Results;
}

} // namespace

EnsureKokkosFunctionCheck::EnsureKokkosFunctionCheck(StringRef Name,
                                                     ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context) {
  AllowIfExplicitHost = std::stoi(Options.get("AllowIfExplicitHost", "0"));
  AllowedFunctionsRegex = Options.get("AllowedFunctionsRegex", "a^");
  // This can't be empty because the regex ast matchers assert !empty
  assert(!AllowedFunctionsRegex.empty());
}

void EnsureKokkosFunctionCheck::storeOptions(
    ClangTidyOptions::OptionMap &Opts) {
  Options.store(Opts, "AllowedFunctionsRegex", AllowedFunctionsRegex);
  Options.store(Opts, "AllowIfExplicitHost",
                std::to_string(AllowIfExplicitHost));
}

void EnsureKokkosFunctionCheck::registerMatchers(MatchFinder *Finder) {
  auto notKCalls = // NOLINT
      callExpr(callee(notKFunc(AllowedFunctionsRegex))).bind("CE");

  // We have to be sure that we don't match functionDecls in systems headers,
  // because they might call our Functor, which if it is a lambda will not be
  // marked with KOKKOS_FUNCTION
  Finder->addMatcher(functionDecl(matchesAttr(KF_Regex),
                                  unless(isExpansionInSystemHeader()),
                                  forEachDescendant(notKCalls))
                         .bind("ParentFD"),
                     this);

  // Need to check the Functor also
  auto Functor = expr(hasType(
      cxxRecordDecl(unless(isExpansionInSystemHeader())).bind("Functor")));
  Finder->addMatcher(callExpr(isKokkosParallelCall(), hasAnyArgument(Functor))
                         .bind("KokkosCE"),
                     this);
}

void EnsureKokkosFunctionCheck::check(const MatchFinder::MatchResult &Result) {

  auto const *ParentFD = Result.Nodes.getNodeAs<FunctionDecl>("ParentFD");
  auto const *CE = Result.Nodes.getNodeAs<CallExpr>("CE");
  auto const *Functor = Result.Nodes.getNodeAs<CXXRecordDecl>("Functor");

  if (ParentFD != nullptr) {
    if (callExprIsToLambaOp(CE)) { // Avoid false positives for local lambdas
      return;
    }

    diag(CE->getBeginLoc(),
         "function %0 called in %1 is missing a KOKKOS_X_FUNCTION annotation")
        << CE->getDirectCallee() << ParentFD;
    diag(CE->getDirectCallee()->getLocation(), "Function %0 declared here",
         DiagnosticIDs::Note)
        << CE->getDirectCallee();
  }

  if (Functor != nullptr) {
    auto const *CE = Result.Nodes.getNodeAs<CallExpr>("KokkosCE");
    if (AllowIfExplicitHost != 0 && explicitlyDefaultHostExecutionSpace(CE)) {
      return;
    }

    if (Functor->isLambda()) {
      auto BadCalls = checkLambdaBody(Functor, AllowedFunctionsRegex);
      for (auto const *BadCall : BadCalls) {
        diag(BadCall->getBeginLoc(),
             "Function %0 called in a lambda was missing "
             "KOKKOS_X_FUNCTION annotation.")
            << BadCall->getDirectCallee();
        diag(BadCall->getDirectCallee()->getBeginLoc(),
             "Function %0 was delcared here", DiagnosticIDs::Note)
            << BadCall->getDirectCallee();
      }
    } else {
      for (auto const *CalledMethod : checkFunctorBody(Functor, CE)) {
        if (isAnnotated(CalledMethod)) {
          continue;
        }

        diag(CE->getBeginLoc(),
             "Called a member function of %0 that requires a "
             "KOKKOS_X_FUNCTION annotation.")
            << CalledMethod->getParent();
        diag(CalledMethod->getBeginLoc(),
             "Member Function %0 of %1 was delcared here", DiagnosticIDs::Note)
            << CalledMethod << CalledMethod->getParent();
      }
    }
  }
}

} // namespace kokkos
} // namespace tidy
} // namespace clang
