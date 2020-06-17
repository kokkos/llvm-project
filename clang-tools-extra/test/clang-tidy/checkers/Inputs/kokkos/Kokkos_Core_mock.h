#pragma once

//
// Standard library stuff that shows up in Kokkos
//
namespace std {
struct string {
  string(const char *);
  ~string();
};
} // namespace std

//
// Global things that show up in Kokkos
//
using size_t = decltype(sizeof(int));
int printf(const char *format, ...);

//
// Kokkos macros
//
#define KOKKOS_LAMBDA [=]
#define KOKKOS_FUNCTION __attribute__((annotate("KOKKOS_FUNCTION")))
#define KOKKOS_INLINE_FUNCTION __attribute__((annotate("KOKKOS_INLINE_FUNCTION")))
#define KOKKOS_FORCEINLINE_FUNCTION __attribute__((annotate("KOKKOS_FORCEINLINE_FUNCTION")))

//
// Kokkos public and semi-public API
//
namespace Kokkos {
namespace Impl {
template <typename IndexType, typename MemberType>
struct TeamThreadRangeBoundariesStruct {
  KOKKOS_INLINE_FUNCTION
  TeamThreadRangeBoundariesStruct(MemberType const &m,
                                  IndexType const &arg_end) {}
};

template <typename IndexType, typename MemberType>
struct ThreadVectorRangeBoundariesStruct {
  KOKKOS_INLINE_FUNCTION
  ThreadVectorRangeBoundariesStruct(MemberType const &m,
                                    IndexType const &arg_end) {}
};
} // namespace Impl

template <class FunctorType>
inline void parallel_for(const size_t work_count,
                         const FunctorType &functor,
                         const std::string &str = "") {}

template <class ExecPolicy, class FunctorType>
inline void parallel_for(const std::string &str,
                         const ExecPolicy &policy,
                         const FunctorType &functor) {}

template <class ExecPolicy, class FunctorType>
inline void parallel_for(const ExecPolicy &policy,
                         const FunctorType &functor,
                         std::string const &str = "") {}

template <class... Properties>
class TeamPolicy {
public:
  using member_type = int;
};

template <typename iType>
KOKKOS_INLINE_FUNCTION
    Impl::TeamThreadRangeBoundariesStruct<iType, TeamPolicy<>::member_type>
    TeamThreadRange(const TeamPolicy<>::member_type &thread, iType count) {
  return Impl::TeamThreadRangeBoundariesStruct<iType,
                                               TeamPolicy<>::member_type>(thread, count);
}

template <typename iType>
KOKKOS_INLINE_FUNCTION
    Impl::ThreadVectorRangeBoundariesStruct<iType, TeamPolicy<>::member_type>
    ThreadVectorRange(const TeamPolicy<>::member_type &thread, iType count) {
  return Impl::ThreadVectorRangeBoundariesStruct<iType,
                                                 TeamPolicy<>::member_type>(thread, count);
}

namespace Impl {
struct SomeHostExecutionSpace {};

template <typename... Properties>
struct PolicyTraits{};
} // namespace Impl

using DefaultExecutionSpace = Impl::SomeHostExecutionSpace;
using DefaultHostExecutionSpace = Impl::SomeHostExecutionSpace;

template <class... Properties>
class RangePolicy : public Impl::PolicyTraits<Properties...>{
public:
  RangePolicy(int, int) {}
};

} // namespace Kokkos
