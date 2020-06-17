// RUN: %check_clang_tidy %s kokkos-implicit-this-capture %t -- -config="{CheckOptions: [{key: kokkos-implicit-this-capture.CheckIfExplicitHost, value: 1}]}" -header-filter=.* -system-headers -- -isystem %S/Inputs/kokkos/

#include "Kokkos_Core_mock.h"

KOKKOS_FUNCTION void do_something(int x) { printf("Got int %d\n", x); }

class BadClass {
  int MyInt = 0;

public:
  void capturesThis() {
    Kokkos::parallel_for(
        Kokkos::RangePolicy<Kokkos::DefaultExecutionSpace>(0,10), 
        [=](int) { do_something(MyInt); });
    // CHECK-MESSAGES: :[[@LINE-1]]:9: warning: Lambda passed to parallel_for implicitly captures this. [kokkos-implicit-this-capture]
  }
};

class GoodClass {
  int MyInt = 0;

public:
  void capturesThis() {
    Kokkos::parallel_for(
        Kokkos::RangePolicy<Kokkos::DefaultHostExecutionSpace>(0,10), 
        KOKKOS_LAMBDA(int) { do_something(MyInt); });
  }
};
