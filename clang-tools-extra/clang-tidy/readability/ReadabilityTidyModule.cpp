//===--- ReadabilityTidyModule.cpp - clang-tidy ---------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "../ClangTidy.h"
#include "../ClangTidyModule.h"
#include "../ClangTidyModuleRegistry.h"
#include "IdentifierNamingCheck.h"

namespace clang::tidy {
namespace readability {

class ReadabilityModule : public ClangTidyModule {
public:
  void addCheckFactories(ClangTidyCheckFactories &CheckFactories) override {
    CheckFactories.registerCheck<IdentifierNamingCheck>(
        "readability-identifier-naming");
  }
};

// Register the ReadabilityModule using this statically initialized variable.
static ClangTidyModuleRegistry::Add<ReadabilityModule>
    X("readability-module", "Adds readability-related checks.");

} // namespace readability

// This anchor is used to force the linker to link in the generated object file
// and thus register the ReadabilityModule.
volatile int ReadabilityModuleAnchorSource = 0;

} // namespace clang::tidy
