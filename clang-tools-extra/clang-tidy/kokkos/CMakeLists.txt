set(LLVM_LINK_COMPONENTS support)

add_clang_library(clangTidyKokkosModule
  EnsureKokkosFunctionCheck.cpp
  ImplicitThisCaptureCheck.cpp
  KokkosMatchers.cpp
  KokkosTidyModule.cpp

  LINK_LIBS
  clangAnalysis
  clangAST
  clangASTMatchers
  clangBasic
  clangLex
  clangTidy
  clangTidyUtils
  )
