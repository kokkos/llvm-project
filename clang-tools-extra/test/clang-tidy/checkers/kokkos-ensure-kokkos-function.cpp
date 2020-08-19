// RUN: %check_clang_tidy %s kokkos-ensure-kokkos-function %t -- -header-filter=.* -system-headers -- -isystem %S/Inputs/kokkos/

#include "Kokkos_Core_mock.h"

KOKKOS_FUNCTION void legal(){}

void foo(){}
KOKKOS_FUNCTION void f(){foo();}
// CHECK-MESSAGES: :[[@LINE-1]]:26: warning: function 'foo' called in 'f' is missing a KOKKOS_X_FUNCTION annotation [kokkos-ensure-kokkos-function]


// FIXME: Add something that doesn't trigger the check here.
KOKKOS_FUNCTION void awesome_f2(){legal();}
