//===-- UncheckedOptionalAccessModel.cpp ------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defines a dataflow analysis that detects unsafe uses of optional
//  values.
//
//===----------------------------------------------------------------------===//

#include "clang/Analysis/FlowSensitive/Models/UncheckedOptionalAccessModel.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/FlowSensitive/CFGMatchSwitch.h"
#include "clang/Analysis/FlowSensitive/DataflowEnvironment.h"
#include "clang/Analysis/FlowSensitive/Formula.h"
#include "clang/Analysis/FlowSensitive/NoopLattice.h"
#include "clang/Analysis/FlowSensitive/StorageLocation.h"
#include "clang/Analysis/FlowSensitive/Value.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include <cassert>
#include <memory>
#include <optional>
#include <utility>

namespace clang {
namespace dataflow {

static bool isTopLevelNamespaceWithName(const NamespaceDecl &NS,
                                        llvm::StringRef Name) {
  return NS.getDeclName().isIdentifier() && NS.getName() == Name &&
         NS.getParent() != nullptr && NS.getParent()->isTranslationUnit();
}

static bool hasOptionalClassName(const CXXRecordDecl &RD) {
  if (!RD.getDeclName().isIdentifier())
    return false;

  if (RD.getName() == "optional") {
    if (const auto *N = dyn_cast_or_null<NamespaceDecl>(RD.getDeclContext()))
      return N->isStdNamespace() || isTopLevelNamespaceWithName(*N, "absl");
    return false;
  }

  if (RD.getName() == "Optional") {
    // Check whether namespace is "::base" or "::folly".
    const auto *N = dyn_cast_or_null<NamespaceDecl>(RD.getDeclContext());
    return N != nullptr && (isTopLevelNamespaceWithName(*N, "base") ||
                            isTopLevelNamespaceWithName(*N, "folly"));
  }

  return false;
}

namespace {

using namespace ::clang::ast_matchers;
using LatticeTransferState = TransferState<NoopLattice>;

AST_MATCHER(CXXRecordDecl, hasOptionalClassNameMatcher) {
  return hasOptionalClassName(Node);
}

DeclarationMatcher optionalClass() {
  return classTemplateSpecializationDecl(
      hasOptionalClassNameMatcher(),
      hasTemplateArgument(0, refersToType(type().bind("T"))));
}

auto optionalOrAliasType() {
  return hasUnqualifiedDesugaredType(
      recordType(hasDeclaration(optionalClass())));
}

/// Matches any of the spellings of the optional types and sugar, aliases, etc.
auto hasOptionalType() { return hasType(optionalOrAliasType()); }

auto isOptionalMemberCallWithNameMatcher(
    ast_matchers::internal::Matcher<NamedDecl> matcher,
    const std::optional<StatementMatcher> &Ignorable = std::nullopt) {
  auto Exception = unless(Ignorable ? expr(anyOf(*Ignorable, cxxThisExpr()))
                                    : cxxThisExpr());
  return cxxMemberCallExpr(
      on(expr(Exception,
              anyOf(hasOptionalType(),
                    hasType(pointerType(pointee(optionalOrAliasType())))))),
      callee(cxxMethodDecl(matcher)));
}

auto isOptionalOperatorCallWithName(
    llvm::StringRef operator_name,
    const std::optional<StatementMatcher> &Ignorable = std::nullopt) {
  return cxxOperatorCallExpr(
      hasOverloadedOperatorName(operator_name),
      callee(cxxMethodDecl(ofClass(optionalClass()))),
      Ignorable ? callExpr(unless(hasArgument(0, *Ignorable))) : callExpr());
}

auto isMakeOptionalCall() {
  return callExpr(callee(functionDecl(hasAnyName(
                      "std::make_optional", "base::make_optional",
                      "absl::make_optional", "folly::make_optional"))),
                  hasOptionalType());
}

auto nulloptTypeDecl() {
  return namedDecl(hasAnyName("std::nullopt_t", "absl::nullopt_t",
                              "base::nullopt_t", "folly::None"));
}

auto hasNulloptType() { return hasType(nulloptTypeDecl()); }

auto inPlaceClass() {
  return recordDecl(hasAnyName("std::in_place_t", "absl::in_place_t",
                               "base::in_place_t", "folly::in_place_t"));
}

auto isOptionalNulloptConstructor() {
  return cxxConstructExpr(
      hasOptionalType(),
      hasDeclaration(cxxConstructorDecl(parameterCountIs(1),
                                        hasParameter(0, hasNulloptType()))));
}

auto isOptionalInPlaceConstructor() {
  return cxxConstructExpr(hasOptionalType(),
                          hasArgument(0, hasType(inPlaceClass())));
}

auto isOptionalValueOrConversionConstructor() {
  return cxxConstructExpr(
      hasOptionalType(),
      unless(hasDeclaration(
          cxxConstructorDecl(anyOf(isCopyConstructor(), isMoveConstructor())))),
      argumentCountIs(1), hasArgument(0, unless(hasNulloptType())));
}

auto isOptionalValueOrConversionAssignment() {
  return cxxOperatorCallExpr(
      hasOverloadedOperatorName("="),
      callee(cxxMethodDecl(ofClass(optionalClass()))),
      unless(hasDeclaration(cxxMethodDecl(
          anyOf(isCopyAssignmentOperator(), isMoveAssignmentOperator())))),
      argumentCountIs(2), hasArgument(1, unless(hasNulloptType())));
}

auto isOptionalNulloptAssignment() {
  return cxxOperatorCallExpr(hasOverloadedOperatorName("="),
                             callee(cxxMethodDecl(ofClass(optionalClass()))),
                             argumentCountIs(2),
                             hasArgument(1, hasNulloptType()));
}

auto isStdSwapCall() {
  return callExpr(callee(functionDecl(hasName("std::swap"))),
                  argumentCountIs(2), hasArgument(0, hasOptionalType()),
                  hasArgument(1, hasOptionalType()));
}

auto isStdForwardCall() {
  return callExpr(callee(functionDecl(hasName("std::forward"))),
                  argumentCountIs(1), hasArgument(0, hasOptionalType()));
}

constexpr llvm::StringLiteral ValueOrCallID = "ValueOrCall";

auto isValueOrStringEmptyCall() {
  // `opt.value_or("").empty()`
  return cxxMemberCallExpr(
      callee(cxxMethodDecl(hasName("empty"))),
      onImplicitObjectArgument(ignoringImplicit(
          cxxMemberCallExpr(on(expr(unless(cxxThisExpr()))),
                            callee(cxxMethodDecl(hasName("value_or"),
                                                 ofClass(optionalClass()))),
                            hasArgument(0, stringLiteral(hasSize(0))))
              .bind(ValueOrCallID))));
}

auto isValueOrNotEqX() {
  auto ComparesToSame = [](ast_matchers::internal::Matcher<Stmt> Arg) {
    return hasOperands(
        ignoringImplicit(
            cxxMemberCallExpr(on(expr(unless(cxxThisExpr()))),
                              callee(cxxMethodDecl(hasName("value_or"),
                                                   ofClass(optionalClass()))),
                              hasArgument(0, Arg))
                .bind(ValueOrCallID)),
        ignoringImplicit(Arg));
  };

  // `opt.value_or(X) != X`, for X is `nullptr`, `""`, or `0`. Ideally, we'd
  // support this pattern for any expression, but the AST does not have a
  // generic expression comparison facility, so we specialize to common cases
  // seen in practice.  FIXME: define a matcher that compares values across
  // nodes, which would let us generalize this to any `X`.
  return binaryOperation(hasOperatorName("!="),
                         anyOf(ComparesToSame(cxxNullPtrLiteralExpr()),
                               ComparesToSame(stringLiteral(hasSize(0))),
                               ComparesToSame(integerLiteral(equals(0)))));
}

auto isCallReturningOptional() {
  return callExpr(hasType(qualType(anyOf(
      optionalOrAliasType(), referenceType(pointee(optionalOrAliasType()))))));
}

template <typename L, typename R>
auto isComparisonOperatorCall(L lhs_arg_matcher, R rhs_arg_matcher) {
  return cxxOperatorCallExpr(
      anyOf(hasOverloadedOperatorName("=="), hasOverloadedOperatorName("!=")),
      argumentCountIs(2), hasArgument(0, lhs_arg_matcher),
      hasArgument(1, rhs_arg_matcher));
}

/// Ensures that `Expr` is mapped to a `BoolValue` and returns its formula.
const Formula &forceBoolValue(Environment &Env, const Expr &Expr) {
  auto *Value = cast_or_null<BoolValue>(Env.getValue(Expr));
  if (Value != nullptr)
    return Value->formula();

  Value = &Env.makeAtomicBoolValue();
  Env.setValue(Expr, *Value);
  return Value->formula();
}

StorageLocation &locForHasValue(const RecordStorageLocation &OptionalLoc) {
  return OptionalLoc.getSyntheticField("has_value");
}

StorageLocation &locForValue(const RecordStorageLocation &OptionalLoc) {
  return OptionalLoc.getSyntheticField("value");
}

/// Sets `HasValueVal` as the symbolic value that represents the "has_value"
/// property of the optional at `OptionalLoc`.
void setHasValue(RecordStorageLocation &OptionalLoc, BoolValue &HasValueVal,
                 Environment &Env) {
  Env.setValue(locForHasValue(OptionalLoc), HasValueVal);
}

/// Creates a symbolic value for an `optional` value at an existing storage
/// location. Uses `HasValueVal` as the symbolic value of the "has_value"
/// property.
RecordValue &createOptionalValue(RecordStorageLocation &Loc,
                                 BoolValue &HasValueVal, Environment &Env) {
  auto &OptionalVal = Env.create<RecordValue>(Loc);
  Env.setValue(Loc, OptionalVal);
  setHasValue(Loc, HasValueVal, Env);
  return OptionalVal;
}

/// Returns the symbolic value that represents the "has_value" property of the
/// optional at `OptionalLoc`. Returns null if `OptionalLoc` is null.
BoolValue *getHasValue(Environment &Env, RecordStorageLocation *OptionalLoc) {
  if (OptionalLoc == nullptr)
    return nullptr;
  StorageLocation &HasValueLoc = locForHasValue(*OptionalLoc);
  auto *HasValueVal = cast_or_null<BoolValue>(Env.getValue(HasValueLoc));
  if (HasValueVal == nullptr) {
    HasValueVal = &Env.makeAtomicBoolValue();
    Env.setValue(HasValueLoc, *HasValueVal);
  }
  return HasValueVal;
}

/// Returns true if and only if `Type` is an optional type.
bool isOptionalType(QualType Type) {
  if (!Type->isRecordType())
    return false;
  const CXXRecordDecl *D = Type->getAsCXXRecordDecl();
  return D != nullptr && hasOptionalClassName(*D);
}

/// Returns the number of optional wrappers in `Type`.
///
/// For example, if `Type` is `optional<optional<int>>`, the result of this
/// function will be 2.
int countOptionalWrappers(const ASTContext &ASTCtx, QualType Type) {
  if (!isOptionalType(Type))
    return 0;
  return 1 + countOptionalWrappers(
                 ASTCtx,
                 cast<ClassTemplateSpecializationDecl>(Type->getAsRecordDecl())
                     ->getTemplateArgs()
                     .get(0)
                     .getAsType()
                     .getDesugaredType(ASTCtx));
}

StorageLocation *getLocBehindPossiblePointer(const Expr &E,
                                             const Environment &Env) {
  if (E.isPRValue()) {
    if (auto *PointerVal = dyn_cast_or_null<PointerValue>(Env.getValue(E)))
      return &PointerVal->getPointeeLoc();
    return nullptr;
  }
  return Env.getStorageLocation(E);
}

void transferUnwrapCall(const Expr *UnwrapExpr, const Expr *ObjectExpr,
                        LatticeTransferState &State) {
  if (auto *OptionalLoc = cast_or_null<RecordStorageLocation>(
          getLocBehindPossiblePointer(*ObjectExpr, State.Env))) {
    if (State.Env.getStorageLocation(*UnwrapExpr) == nullptr)
      State.Env.setStorageLocation(*UnwrapExpr, locForValue(*OptionalLoc));
  }
}

void transferArrowOpCall(const Expr *UnwrapExpr, const Expr *ObjectExpr,
                         LatticeTransferState &State) {
  if (auto *OptionalLoc = cast_or_null<RecordStorageLocation>(
          getLocBehindPossiblePointer(*ObjectExpr, State.Env)))
    State.Env.setValue(
        *UnwrapExpr, State.Env.create<PointerValue>(locForValue(*OptionalLoc)));
}

void transferMakeOptionalCall(const CallExpr *E,
                              const MatchFinder::MatchResult &,
                              LatticeTransferState &State) {
  State.Env.setValue(
      *E, createOptionalValue(State.Env.getResultObjectLocation(*E),
                              State.Env.getBoolLiteralValue(true), State.Env));
}

void transferOptionalHasValueCall(const CXXMemberCallExpr *CallExpr,
                                  const MatchFinder::MatchResult &,
                                  LatticeTransferState &State) {
  if (auto *HasValueVal = getHasValue(
          State.Env, getImplicitObjectLocation(*CallExpr, State.Env))) {
    State.Env.setValue(*CallExpr, *HasValueVal);
  }
}

/// `ModelPred` builds a logical formula relating the predicate in
/// `ValueOrPredExpr` to the optional's `has_value` property.
void transferValueOrImpl(
    const clang::Expr *ValueOrPredExpr, const MatchFinder::MatchResult &Result,
    LatticeTransferState &State,
    const Formula &(*ModelPred)(Environment &Env, const Formula &ExprVal,
                                const Formula &HasValueVal)) {
  auto &Env = State.Env;

  const auto *MCE =
      Result.Nodes.getNodeAs<clang::CXXMemberCallExpr>(ValueOrCallID);

  auto *HasValueVal =
      getHasValue(State.Env, getImplicitObjectLocation(*MCE, State.Env));
  if (HasValueVal == nullptr)
    return;

  Env.assume(ModelPred(Env, forceBoolValue(Env, *ValueOrPredExpr),
                       HasValueVal->formula()));
}

void transferValueOrStringEmptyCall(const clang::Expr *ComparisonExpr,
                                    const MatchFinder::MatchResult &Result,
                                    LatticeTransferState &State) {
  return transferValueOrImpl(ComparisonExpr, Result, State,
                             [](Environment &Env, const Formula &ExprVal,
                                const Formula &HasValueVal) -> const Formula & {
                               auto &A = Env.arena();
                               // If the result is *not* empty, then we know the
                               // optional must have been holding a value. If
                               // `ExprVal` is true, though, we don't learn
                               // anything definite about `has_value`, so we
                               // don't add any corresponding implications to
                               // the flow condition.
                               return A.makeImplies(A.makeNot(ExprVal),
                                                    HasValueVal);
                             });
}

void transferValueOrNotEqX(const Expr *ComparisonExpr,
                           const MatchFinder::MatchResult &Result,
                           LatticeTransferState &State) {
  transferValueOrImpl(ComparisonExpr, Result, State,
                      [](Environment &Env, const Formula &ExprVal,
                         const Formula &HasValueVal) -> const Formula & {
                        auto &A = Env.arena();
                        // We know that if `(opt.value_or(X) != X)` then
                        // `opt.hasValue()`, even without knowing further
                        // details about the contents of `opt`.
                        return A.makeImplies(ExprVal, HasValueVal);
                      });
}

void transferCallReturningOptional(const CallExpr *E,
                                   const MatchFinder::MatchResult &Result,
                                   LatticeTransferState &State) {
  if (State.Env.getValue(*E) != nullptr)
    return;

  RecordStorageLocation *Loc = nullptr;
  if (E->isPRValue()) {
    Loc = &State.Env.getResultObjectLocation(*E);
  } else {
    Loc = cast_or_null<RecordStorageLocation>(State.Env.getStorageLocation(*E));
    if (Loc == nullptr) {
      Loc = &cast<RecordStorageLocation>(State.Env.createStorageLocation(*E));
      State.Env.setStorageLocation(*E, *Loc);
    }
  }

  RecordValue &Val =
      createOptionalValue(*Loc, State.Env.makeAtomicBoolValue(), State.Env);
  if (E->isPRValue())
    State.Env.setValue(*E, Val);
}

void constructOptionalValue(const Expr &E, Environment &Env,
                            BoolValue &HasValueVal) {
  RecordStorageLocation &Loc = Env.getResultObjectLocation(E);
  Env.setValue(E, createOptionalValue(Loc, HasValueVal, Env));
}

/// Returns a symbolic value for the "has_value" property of an `optional<T>`
/// value that is constructed/assigned from a value of type `U` or `optional<U>`
/// where `T` is constructible from `U`.
BoolValue &valueOrConversionHasValue(const FunctionDecl &F, const Expr &E,
                                     const MatchFinder::MatchResult &MatchRes,
                                     LatticeTransferState &State) {
  assert(F.getTemplateSpecializationArgs() != nullptr);
  assert(F.getTemplateSpecializationArgs()->size() > 0);

  const int TemplateParamOptionalWrappersCount =
      countOptionalWrappers(*MatchRes.Context, F.getTemplateSpecializationArgs()
                                                   ->get(0)
                                                   .getAsType()
                                                   .getNonReferenceType());
  const int ArgTypeOptionalWrappersCount = countOptionalWrappers(
      *MatchRes.Context, E.getType().getNonReferenceType());

  // Check if this is a constructor/assignment call for `optional<T>` with
  // argument of type `U` such that `T` is constructible from `U`.
  if (TemplateParamOptionalWrappersCount == ArgTypeOptionalWrappersCount)
    return State.Env.getBoolLiteralValue(true);

  // This is a constructor/assignment call for `optional<T>` with argument of
  // type `optional<U>` such that `T` is constructible from `U`.
  auto *Loc =
      cast_or_null<RecordStorageLocation>(State.Env.getStorageLocation(E));
  if (auto *HasValueVal = getHasValue(State.Env, Loc))
    return *HasValueVal;
  return State.Env.makeAtomicBoolValue();
}

void transferValueOrConversionConstructor(
    const CXXConstructExpr *E, const MatchFinder::MatchResult &MatchRes,
    LatticeTransferState &State) {
  assert(E->getNumArgs() > 0);

  constructOptionalValue(*E, State.Env,
                         valueOrConversionHasValue(*E->getConstructor(),
                                                   *E->getArg(0), MatchRes,
                                                   State));
}

void transferAssignment(const CXXOperatorCallExpr *E, BoolValue &HasValueVal,
                        LatticeTransferState &State) {
  assert(E->getNumArgs() > 0);

  if (auto *Loc = cast_or_null<RecordStorageLocation>(
          State.Env.getStorageLocation(*E->getArg(0)))) {
    createOptionalValue(*Loc, HasValueVal, State.Env);

    // Assign a storage location for the whole expression.
    State.Env.setStorageLocation(*E, *Loc);
  }
}

void transferValueOrConversionAssignment(
    const CXXOperatorCallExpr *E, const MatchFinder::MatchResult &MatchRes,
    LatticeTransferState &State) {
  assert(E->getNumArgs() > 1);
  transferAssignment(E,
                     valueOrConversionHasValue(*E->getDirectCallee(),
                                               *E->getArg(1), MatchRes, State),
                     State);
}

void transferNulloptAssignment(const CXXOperatorCallExpr *E,
                               const MatchFinder::MatchResult &,
                               LatticeTransferState &State) {
  transferAssignment(E, State.Env.getBoolLiteralValue(false), State);
}

void transferSwap(RecordStorageLocation *Loc1, RecordStorageLocation *Loc2,
                  Environment &Env) {
  // We account for cases where one or both of the optionals are not modeled,
  // either lacking associated storage locations, or lacking values associated
  // to such storage locations.

  if (Loc1 == nullptr) {
    if (Loc2 != nullptr)
      createOptionalValue(*Loc2, Env.makeAtomicBoolValue(), Env);
    return;
  }
  if (Loc2 == nullptr) {
    createOptionalValue(*Loc1, Env.makeAtomicBoolValue(), Env);
    return;
  }

  // Both expressions have locations, though they may not have corresponding
  // values. In that case, we create a fresh value at this point. Note that if
  // two branches both do this, they will not share the value, but it at least
  // allows for local reasoning about the value. To avoid the above, we would
  // need *lazy* value allocation.
  // FIXME: allocate values lazily, instead of just creating a fresh value.
  BoolValue *BoolVal1 = getHasValue(Env, Loc1);
  if (BoolVal1 == nullptr)
    BoolVal1 = &Env.makeAtomicBoolValue();

  BoolValue *BoolVal2 = getHasValue(Env, Loc2);
  if (BoolVal2 == nullptr)
    BoolVal2 = &Env.makeAtomicBoolValue();

  createOptionalValue(*Loc1, *BoolVal2, Env);
  createOptionalValue(*Loc2, *BoolVal1, Env);
}

void transferSwapCall(const CXXMemberCallExpr *E,
                      const MatchFinder::MatchResult &,
                      LatticeTransferState &State) {
  assert(E->getNumArgs() == 1);
  auto *OtherLoc = cast_or_null<RecordStorageLocation>(
      State.Env.getStorageLocation(*E->getArg(0)));
  transferSwap(getImplicitObjectLocation(*E, State.Env), OtherLoc, State.Env);
}

void transferStdSwapCall(const CallExpr *E, const MatchFinder::MatchResult &,
                         LatticeTransferState &State) {
  assert(E->getNumArgs() == 2);
  auto *Arg0Loc = cast_or_null<RecordStorageLocation>(
      State.Env.getStorageLocation(*E->getArg(0)));
  auto *Arg1Loc = cast_or_null<RecordStorageLocation>(
      State.Env.getStorageLocation(*E->getArg(1)));
  transferSwap(Arg0Loc, Arg1Loc, State.Env);
}

void transferStdForwardCall(const CallExpr *E, const MatchFinder::MatchResult &,
                            LatticeTransferState &State) {
  assert(E->getNumArgs() == 1);

  if (auto *Loc = State.Env.getStorageLocation(*E->getArg(0)))
    State.Env.setStorageLocation(*E, *Loc);
}

const Formula &evaluateEquality(Arena &A, const Formula &EqVal,
                                const Formula &LHS, const Formula &RHS) {
  // Logically, an optional<T> object is composed of two values - a `has_value`
  // bit and a value of type T. Equality of optional objects compares both
  // values. Therefore, merely comparing the `has_value` bits isn't sufficient:
  // when two optional objects are engaged, the equality of their respective
  // values of type T matters. Since we only track the `has_value` bits, we
  // can't make any conclusions about equality when we know that two optional
  // objects are engaged.
  //
  // We express this as two facts about the equality:
  // a) EqVal => (LHS & RHS) v (!RHS & !LHS)
  //    If they are equal, then either both are set or both are unset.
  // b) (!LHS & !RHS) => EqVal
  //    If neither is set, then they are equal.
  // We rewrite b) as !EqVal => (LHS v RHS), for a more compact formula.
  return A.makeAnd(
      A.makeImplies(EqVal, A.makeOr(A.makeAnd(LHS, RHS),
                                    A.makeAnd(A.makeNot(LHS), A.makeNot(RHS)))),
      A.makeImplies(A.makeNot(EqVal), A.makeOr(LHS, RHS)));
}

void transferOptionalAndOptionalCmp(const clang::CXXOperatorCallExpr *CmpExpr,
                                    const MatchFinder::MatchResult &,
                                    LatticeTransferState &State) {
  Environment &Env = State.Env;
  auto &A = Env.arena();
  auto *CmpValue = &forceBoolValue(Env, *CmpExpr);
  auto *Arg0Loc = cast_or_null<RecordStorageLocation>(
      Env.getStorageLocation(*CmpExpr->getArg(0)));
  if (auto *LHasVal = getHasValue(Env, Arg0Loc)) {
    auto *Arg1Loc = cast_or_null<RecordStorageLocation>(
        Env.getStorageLocation(*CmpExpr->getArg(1)));
    if (auto *RHasVal = getHasValue(Env, Arg1Loc)) {
      if (CmpExpr->getOperator() == clang::OO_ExclaimEqual)
        CmpValue = &A.makeNot(*CmpValue);
      Env.assume(evaluateEquality(A, *CmpValue, LHasVal->formula(),
                                  RHasVal->formula()));
    }
  }
}

void transferOptionalAndValueCmp(const clang::CXXOperatorCallExpr *CmpExpr,
                                 const clang::Expr *E, Environment &Env) {
  auto &A = Env.arena();
  auto *CmpValue = &forceBoolValue(Env, *CmpExpr);
  auto *Loc = cast_or_null<RecordStorageLocation>(Env.getStorageLocation(*E));
  if (auto *HasVal = getHasValue(Env, Loc)) {
    if (CmpExpr->getOperator() == clang::OO_ExclaimEqual)
      CmpValue = &A.makeNot(*CmpValue);
    Env.assume(
        evaluateEquality(A, *CmpValue, HasVal->formula(), A.makeLiteral(true)));
  }
}

void transferOptionalAndNulloptCmp(const clang::CXXOperatorCallExpr *CmpExpr,
                                   const clang::Expr *E, Environment &Env) {
  auto &A = Env.arena();
  auto *CmpValue = &forceBoolValue(Env, *CmpExpr);
  auto *Loc = cast_or_null<RecordStorageLocation>(Env.getStorageLocation(*E));
  if (auto *HasVal = getHasValue(Env, Loc)) {
    if (CmpExpr->getOperator() == clang::OO_ExclaimEqual)
      CmpValue = &A.makeNot(*CmpValue);
    Env.assume(evaluateEquality(A, *CmpValue, HasVal->formula(),
                                A.makeLiteral(false)));
  }
}

std::optional<StatementMatcher>
ignorableOptional(const UncheckedOptionalAccessModelOptions &Options) {
  if (Options.IgnoreSmartPointerDereference) {
    auto SmartPtrUse = expr(ignoringParenImpCasts(cxxOperatorCallExpr(
        anyOf(hasOverloadedOperatorName("->"), hasOverloadedOperatorName("*")),
        unless(hasArgument(0, expr(hasOptionalType()))))));
    return expr(
        anyOf(SmartPtrUse, memberExpr(hasObjectExpression(SmartPtrUse))));
  }
  return std::nullopt;
}

StatementMatcher
valueCall(const std::optional<StatementMatcher> &IgnorableOptional) {
  return isOptionalMemberCallWithNameMatcher(hasName("value"),
                                             IgnorableOptional);
}

StatementMatcher
valueOperatorCall(const std::optional<StatementMatcher> &IgnorableOptional) {
  return expr(anyOf(isOptionalOperatorCallWithName("*", IgnorableOptional),
                    isOptionalOperatorCallWithName("->", IgnorableOptional)));
}

auto buildTransferMatchSwitch() {
  // FIXME: Evaluate the efficiency of matchers. If using matchers results in a
  // lot of duplicated work (e.g. string comparisons), consider providing APIs
  // that avoid it through memoization.
  return CFGMatchSwitchBuilder<LatticeTransferState>()
      // make_optional
      .CaseOfCFGStmt<CallExpr>(isMakeOptionalCall(), transferMakeOptionalCall)

      // optional::optional (in place)
      .CaseOfCFGStmt<CXXConstructExpr>(
          isOptionalInPlaceConstructor(),
          [](const CXXConstructExpr *E, const MatchFinder::MatchResult &,
             LatticeTransferState &State) {
            constructOptionalValue(*E, State.Env,
                                   State.Env.getBoolLiteralValue(true));
          })
      // optional::optional(nullopt_t)
      .CaseOfCFGStmt<CXXConstructExpr>(
          isOptionalNulloptConstructor(),
          [](const CXXConstructExpr *E, const MatchFinder::MatchResult &,
             LatticeTransferState &State) {
            constructOptionalValue(*E, State.Env,
                                   State.Env.getBoolLiteralValue(false));
          })
      // optional::optional (value/conversion)
      .CaseOfCFGStmt<CXXConstructExpr>(isOptionalValueOrConversionConstructor(),
                                       transferValueOrConversionConstructor)

      // optional::operator=
      .CaseOfCFGStmt<CXXOperatorCallExpr>(
          isOptionalValueOrConversionAssignment(),
          transferValueOrConversionAssignment)
      .CaseOfCFGStmt<CXXOperatorCallExpr>(isOptionalNulloptAssignment(),
                                          transferNulloptAssignment)

      // optional::value
      .CaseOfCFGStmt<CXXMemberCallExpr>(
          valueCall(std::nullopt),
          [](const CXXMemberCallExpr *E, const MatchFinder::MatchResult &,
             LatticeTransferState &State) {
            transferUnwrapCall(E, E->getImplicitObjectArgument(), State);
          })

      // optional::operator*
      .CaseOfCFGStmt<CallExpr>(isOptionalOperatorCallWithName("*"),
                               [](const CallExpr *E,
                                  const MatchFinder::MatchResult &,
                                  LatticeTransferState &State) {
                                 transferUnwrapCall(E, E->getArg(0), State);
                               })

      // optional::operator->
      .CaseOfCFGStmt<CallExpr>(isOptionalOperatorCallWithName("->"),
                               [](const CallExpr *E,
                                  const MatchFinder::MatchResult &,
                                  LatticeTransferState &State) {
                                 transferArrowOpCall(E, E->getArg(0), State);
                               })

      // optional::has_value, optional::hasValue
      // Of the supported optionals only folly::Optional uses hasValue, but this
      // will also pass for other types
      .CaseOfCFGStmt<CXXMemberCallExpr>(
          isOptionalMemberCallWithNameMatcher(
              hasAnyName("has_value", "hasValue")),
          transferOptionalHasValueCall)

      // optional::operator bool
      .CaseOfCFGStmt<CXXMemberCallExpr>(
          isOptionalMemberCallWithNameMatcher(hasName("operator bool")),
          transferOptionalHasValueCall)

      // optional::emplace
      .CaseOfCFGStmt<CXXMemberCallExpr>(
          isOptionalMemberCallWithNameMatcher(hasName("emplace")),
          [](const CXXMemberCallExpr *E, const MatchFinder::MatchResult &,
             LatticeTransferState &State) {
            if (RecordStorageLocation *Loc =
                    getImplicitObjectLocation(*E, State.Env)) {
              createOptionalValue(*Loc, State.Env.getBoolLiteralValue(true),
                                  State.Env);
            }
          })

      // optional::reset
      .CaseOfCFGStmt<CXXMemberCallExpr>(
          isOptionalMemberCallWithNameMatcher(hasName("reset")),
          [](const CXXMemberCallExpr *E, const MatchFinder::MatchResult &,
             LatticeTransferState &State) {
            if (RecordStorageLocation *Loc =
                    getImplicitObjectLocation(*E, State.Env)) {
              createOptionalValue(*Loc, State.Env.getBoolLiteralValue(false),
                                  State.Env);
            }
          })

      // optional::swap
      .CaseOfCFGStmt<CXXMemberCallExpr>(
          isOptionalMemberCallWithNameMatcher(hasName("swap")),
          transferSwapCall)

      // std::swap
      .CaseOfCFGStmt<CallExpr>(isStdSwapCall(), transferStdSwapCall)

      // std::forward
      .CaseOfCFGStmt<CallExpr>(isStdForwardCall(), transferStdForwardCall)

      // opt.value_or("").empty()
      .CaseOfCFGStmt<Expr>(isValueOrStringEmptyCall(),
                           transferValueOrStringEmptyCall)

      // opt.value_or(X) != X
      .CaseOfCFGStmt<Expr>(isValueOrNotEqX(), transferValueOrNotEqX)

      // Comparisons (==, !=):
      .CaseOfCFGStmt<CXXOperatorCallExpr>(
          isComparisonOperatorCall(hasOptionalType(), hasOptionalType()),
          transferOptionalAndOptionalCmp)
      .CaseOfCFGStmt<CXXOperatorCallExpr>(
          isComparisonOperatorCall(hasOptionalType(), hasNulloptType()),
          [](const clang::CXXOperatorCallExpr *Cmp,
             const MatchFinder::MatchResult &, LatticeTransferState &State) {
            transferOptionalAndNulloptCmp(Cmp, Cmp->getArg(0), State.Env);
          })
      .CaseOfCFGStmt<CXXOperatorCallExpr>(
          isComparisonOperatorCall(hasNulloptType(), hasOptionalType()),
          [](const clang::CXXOperatorCallExpr *Cmp,
             const MatchFinder::MatchResult &, LatticeTransferState &State) {
            transferOptionalAndNulloptCmp(Cmp, Cmp->getArg(1), State.Env);
          })
      .CaseOfCFGStmt<CXXOperatorCallExpr>(
          isComparisonOperatorCall(
              hasOptionalType(),
              unless(anyOf(hasOptionalType(), hasNulloptType()))),
          [](const clang::CXXOperatorCallExpr *Cmp,
             const MatchFinder::MatchResult &, LatticeTransferState &State) {
            transferOptionalAndValueCmp(Cmp, Cmp->getArg(0), State.Env);
          })
      .CaseOfCFGStmt<CXXOperatorCallExpr>(
          isComparisonOperatorCall(
              unless(anyOf(hasOptionalType(), hasNulloptType())),
              hasOptionalType()),
          [](const clang::CXXOperatorCallExpr *Cmp,
             const MatchFinder::MatchResult &, LatticeTransferState &State) {
            transferOptionalAndValueCmp(Cmp, Cmp->getArg(1), State.Env);
          })

      // returns optional
      .CaseOfCFGStmt<CallExpr>(isCallReturningOptional(),
                               transferCallReturningOptional)

      .Build();
}

llvm::SmallVector<SourceLocation> diagnoseUnwrapCall(const Expr *ObjectExpr,
                                                     const Environment &Env) {
  if (auto *OptionalLoc = cast_or_null<RecordStorageLocation>(
          getLocBehindPossiblePointer(*ObjectExpr, Env))) {
    auto *Prop = Env.getValue(locForHasValue(*OptionalLoc));
    if (auto *HasValueVal = cast_or_null<BoolValue>(Prop)) {
      if (Env.proves(HasValueVal->formula()))
        return {};
    }
  }

  // Record that this unwrap is *not* provably safe.
  // FIXME: include either the name of the optional (if applicable) or a source
  // range of the access for easier interpretation of the result.
  return {ObjectExpr->getBeginLoc()};
}

auto buildDiagnoseMatchSwitch(
    const UncheckedOptionalAccessModelOptions &Options) {
  // FIXME: Evaluate the efficiency of matchers. If using matchers results in a
  // lot of duplicated work (e.g. string comparisons), consider providing APIs
  // that avoid it through memoization.
  auto IgnorableOptional = ignorableOptional(Options);
  return CFGMatchSwitchBuilder<const Environment,
                               llvm::SmallVector<SourceLocation>>()
      // optional::value
      .CaseOfCFGStmt<CXXMemberCallExpr>(
          valueCall(IgnorableOptional),
          [](const CXXMemberCallExpr *E, const MatchFinder::MatchResult &,
             const Environment &Env) {
            return diagnoseUnwrapCall(E->getImplicitObjectArgument(), Env);
          })

      // optional::operator*, optional::operator->
      .CaseOfCFGStmt<CallExpr>(valueOperatorCall(IgnorableOptional),
                               [](const CallExpr *E,
                                  const MatchFinder::MatchResult &,
                                  const Environment &Env) {
                                 return diagnoseUnwrapCall(E->getArg(0), Env);
                               })
      .Build();
}

} // namespace

ast_matchers::DeclarationMatcher
UncheckedOptionalAccessModel::optionalClassDecl() {
  return optionalClass();
}

static QualType valueTypeFromOptionalType(QualType OptionalTy) {
  auto *CTSD =
      cast<ClassTemplateSpecializationDecl>(OptionalTy->getAsCXXRecordDecl());
  return CTSD->getTemplateArgs()[0].getAsType();
}

UncheckedOptionalAccessModel::UncheckedOptionalAccessModel(ASTContext &Ctx,
                                                           Environment &Env)
    : DataflowAnalysis<UncheckedOptionalAccessModel, NoopLattice>(Ctx),
      TransferMatchSwitch(buildTransferMatchSwitch()) {
  Env.getDataflowAnalysisContext().setSyntheticFieldCallback(
      [&Ctx](QualType Ty) -> llvm::StringMap<QualType> {
        if (!isOptionalType(Ty))
          return {};
        return {{"value", valueTypeFromOptionalType(Ty)},
                {"has_value", Ctx.BoolTy}};
      });
}

void UncheckedOptionalAccessModel::transfer(const CFGElement &Elt,
                                            NoopLattice &L, Environment &Env) {
  LatticeTransferState State(L, Env);
  TransferMatchSwitch(Elt, getASTContext(), State);
}

UncheckedOptionalAccessDiagnoser::UncheckedOptionalAccessDiagnoser(
    UncheckedOptionalAccessModelOptions Options)
    : DiagnoseMatchSwitch(buildDiagnoseMatchSwitch(Options)) {}

} // namespace dataflow
} // namespace clang
