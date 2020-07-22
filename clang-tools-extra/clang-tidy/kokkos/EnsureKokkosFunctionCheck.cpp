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

namespace clang {
namespace tidy {
namespace kokkos {
namespace {

std::string KF_Regex = "KOKKOS_.*FUNCTION";

bool isAnnotated(CXXMethodDecl const *Method) {
  // If the method is annotated the match will not be empty
  return !match(cxxMethodDecl(matchesAttr(KF_Regex)), *Method,
                Method->getASTContext())
              .empty();
}

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

  // Match all callexprs in out body
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
  AllowedFunctionsRegex = Options.get("AllowedFunctionsRegex", "");
}

void EnsureKokkosFunctionCheck::storeOptions(
    ClangTidyOptions::OptionMap &Opts) {
  Options.store(Opts, "AllowedFunctionsRegex", AllowedFunctionsRegex);
  Options.store(Opts, "AllowIfExplicitHost",
                std::to_string(AllowIfExplicitHost));
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
    diag(CE->getBeginLoc(),
         "function %0 called in %1 is missing a KOKKOS_X_FUNCTION annotation")
        << CE->getDirectCallee() << ParentFD;
    diag(CE->getDirectCallee()->getLocation(), "Function %0 declared here",
         DiagnosticIDs::Note)
        << CE->getDirectCallee();
  }

  if (Functor != nullptr) {
    auto const *CE = Result.Nodes.getNodeAs<CallExpr>("KokkosCE");
    if (AllowIfExplicitHost != 0 && explicitDefaultHostExecutionSpace(CE)) {
      return;
    }

    if (Functor->isLambda()) {
      auto const *BadCall = checkLambdaBody(Functor, AllowedFunctionsRegex);
      if (BadCall) {
        diag(BadCall->getBeginLoc(),
             "Function %0 called in a lambda was missing "
             "KOKKOS_X_FUNCTION annotation.")
            << BadCall->getDirectCallee();
      }
    } else {
      for (auto const *CalledMethod : checkFunctorBody(Functor, CE)) {
        if (isAnnotated(CalledMethod)) {
          continue;
        }

        diag(CalledMethod->getBeginLoc(), "Member Function of %0, requires a "
                                          "KOKKOS_X_FUNCTION annotation.")
            << CalledMethod->getParent();
      }
    }
  }
}

} // namespace kokkos
} // namespace tidy
} // namespace clang
