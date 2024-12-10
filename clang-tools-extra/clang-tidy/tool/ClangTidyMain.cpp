//===--- tools/extra/clang-tidy/ClangTidyMain.cpp - Clang tidy tool -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
///  \file This file implements a clang-tidy tool.
///
///  This tool uses the Clang Tooling infrastructure, see
///    http://clang.llvm.org/docs/HowToSetupToolingForLLVM.html
///  for details on setting it up with LLVM source tree.
///
//===----------------------------------------------------------------------===//

#include "ClangTidyMain.h"
#include "../ClangTidy.h"
#include "../ClangTidyForceLinker.h"
#include "../ClangTidyModuleRegistry.h"
#include "../ClangTidyOptions.h"
#include "../GlobList.h"
#include "../readability/IdentifierNamingCheck.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/LLVM.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBufferRef.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/PluginLoader.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/YAMLTraits.h"
#include <optional>

using namespace clang;
using namespace clang::tooling;
using namespace llvm;
using namespace clang::tidy;
using namespace clang::tidy::readability;

namespace {

static std::unique_ptr<ClangTidyOptionsProvider>
createOptionsProvider(llvm::IntrusiveRefCntPtr<vfs::FileSystem> FS) {
  ClangTidyGlobalOptions GlobalOptions;

  ClangTidyOptions DefaultOptions;
  DefaultOptions.Checks = "-*,readability-identifier-naming";
  DefaultOptions.WarningsAsErrors = "";
  DefaultOptions.HeaderFilterRegex = "";
  DefaultOptions.ExcludeHeaderFilterRegex = "";
  DefaultOptions.SystemHeaders = false;
  DefaultOptions.FormatStyle = "none";
  DefaultOptions.User = llvm::sys::Process::GetEnv("USER");
  // USERNAME is used on Windows.
  if (!DefaultOptions.User)
    DefaultOptions.User = llvm::sys::Process::GetEnv("USERNAME");

  ClangTidyOptions OverrideOptions;

  llvm::ErrorOr<ClangTidyOptions> ParsedConfig =
      clang::tidy::parseConfiguration(MemoryBufferRef(
          "{CheckOptions: [ {key: readability-identifier-naming.ClassCase, "
          "value: CamelCase} ]}",
          "<command-line-config>"));
  if (ParsedConfig)
    return std::make_unique<ConfigOptionsProvider>(
        std::move(GlobalOptions),
        ClangTidyOptions::getDefaults().merge(DefaultOptions, 0),
        std::move(*ParsedConfig), std::move(OverrideOptions), std::move(FS));
  llvm::errs() << "Error: invalid configuration specified.\n"
               << ParsedConfig.getError().message() << "\n";
  return nullptr;
}

// Copy/ Paste from RenamerClangTidyVisitor.

class NameLookup {
  llvm::PointerIntPair<const NamedDecl *, 1, bool> Data;

public:
  explicit NameLookup(const NamedDecl *ND) : Data(ND, false) {}
  explicit NameLookup(std::nullopt_t) : Data(nullptr, true) {}
  explicit NameLookup(std::nullptr_t) : Data(nullptr, false) {}
  NameLookup() : NameLookup(nullptr) {}

  bool hasMultipleResolutions() const { return Data.getInt(); }
  const NamedDecl *getDecl() const {
    assert(!hasMultipleResolutions() && "Found multiple decls");
    return Data.getPointer();
  }
  operator bool() const { return !hasMultipleResolutions(); }
  const NamedDecl *operator*() const { return getDecl(); }
};

static const NamedDecl *findDecl(const RecordDecl &RecDecl,
                                 StringRef DeclName) {
  for (const Decl *D : RecDecl.decls()) {
    if (const auto *ND = dyn_cast<NamedDecl>(D)) {
      if (ND->getDeclName().isIdentifier() && ND->getName() == DeclName)
        return ND;
    }
  }
  return nullptr;
}

static NameLookup findDeclInBases(const CXXRecordDecl &Parent,
                                  StringRef DeclName,
                                  bool AggressiveTemplateLookup) {
  if (!Parent.hasDefinition())
    return NameLookup(nullptr);
  if (const NamedDecl *InClassRef = findDecl(Parent, DeclName))
    return NameLookup(InClassRef);
  const NamedDecl *Found = nullptr;

  for (CXXBaseSpecifier Base : Parent.bases()) {
    const auto *Record = Base.getType()->getAsCXXRecordDecl();
    if (!Record && AggressiveTemplateLookup) {
      if (const auto *TST =
              Base.getType()->getAs<TemplateSpecializationType>()) {
        if (const auto *TD = llvm::dyn_cast_or_null<ClassTemplateDecl>(
                TST->getTemplateName().getAsTemplateDecl()))
          Record = TD->getTemplatedDecl();
      }
    }
    if (!Record)
      continue;
    if (auto Search =
            findDeclInBases(*Record, DeclName, AggressiveTemplateLookup)) {
      if (*Search) {
        if (Found)
          return NameLookup(
              std::nullopt); // Multiple decls found in different base classes.
        Found = *Search;
        continue;
      }
    } else
      return NameLookup(std::nullopt); // Propagate multiple resolution back up.
  }
  return NameLookup(Found); // If nullptr, decl wasn't found.
}

class RenamerClangTidyVisitor
    : public RecursiveASTVisitor<RenamerClangTidyVisitor> {
public:
  RenamerClangTidyVisitor(RenamerClangTidyCheck *Check, const SourceManager &SM,
                          bool AggressiveDependentMemberLookup)
      : Check(Check), SM(SM),
        AggressiveDependentMemberLookup(AggressiveDependentMemberLookup) {}

  bool shouldVisitTemplateInstantiations() const { return true; }

  bool shouldVisitImplicitCode() const { return false; }

  bool VisitCXXConstructorDecl(CXXConstructorDecl *Decl) {
    if (Decl->isImplicit())
      return true;
    Check->addUsage(Decl->getParent(), Decl->getNameInfo().getSourceRange(),
                    SM);

    for (const auto *Init : Decl->inits()) {
      if (!Init->isWritten() || Init->isInClassMemberInitializer())
        continue;
      if (const FieldDecl *FD = Init->getAnyMember())
        Check->addUsage(FD, SourceRange(Init->getMemberLocation()), SM);
      // Note: delegating constructors and base class initializers are handled
      // via the "typeLoc" matcher.
    }

    return true;
  }

  bool VisitCXXDestructorDecl(CXXDestructorDecl *Decl) {
    if (Decl->isImplicit())
      return true;
    SourceRange Range = Decl->getNameInfo().getSourceRange();
    if (Range.getBegin().isInvalid())
      return true;

    // The first token that will be found is the ~ (or the equivalent trigraph),
    // we want instead to replace the next token, that will be the identifier.
    Range.setBegin(CharSourceRange::getTokenRange(Range).getEnd());
    Check->addUsage(Decl->getParent(), Range, SM);
    return true;
  }

  bool VisitUsingDecl(UsingDecl *Decl) {
    for (const auto *Shadow : Decl->shadows())
      Check->addUsage(Shadow->getTargetDecl(),
                      Decl->getNameInfo().getSourceRange(), SM);
    return true;
  }

  bool VisitUsingDirectiveDecl(UsingDirectiveDecl *Decl) {
    Check->addUsage(Decl->getNominatedNamespaceAsWritten(),
                    Decl->getIdentLocation(), SM);
    return true;
  }

  bool VisitNamedDecl(NamedDecl *Decl) {
    SourceRange UsageRange =
        DeclarationNameInfo(Decl->getDeclName(), Decl->getLocation())
            .getSourceRange();
    Check->addUsage(Decl, UsageRange, SM);
    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *DeclRef) {
    SourceRange Range = DeclRef->getNameInfo().getSourceRange();
    Check->addUsage(DeclRef->getDecl(), Range, SM);
    return true;
  }

  bool TraverseNestedNameSpecifierLoc(NestedNameSpecifierLoc Loc) {
    if (const NestedNameSpecifier *Spec = Loc.getNestedNameSpecifier()) {
      if (const NamespaceDecl *Decl = Spec->getAsNamespace())
        Check->addUsage(Decl, Loc.getLocalSourceRange(), SM);
    }

    using Base = RecursiveASTVisitor<RenamerClangTidyVisitor>;
    return Base::TraverseNestedNameSpecifierLoc(Loc);
  }

  bool VisitMemberExpr(MemberExpr *MemberRef) {
    SourceRange Range = MemberRef->getMemberNameInfo().getSourceRange();
    Check->addUsage(MemberRef->getMemberDecl(), Range, SM);
    return true;
  }

  bool
  VisitCXXDependentScopeMemberExpr(CXXDependentScopeMemberExpr *DepMemberRef) {
    QualType BaseType = DepMemberRef->isArrow()
                            ? DepMemberRef->getBaseType()->getPointeeType()
                            : DepMemberRef->getBaseType();
    if (BaseType.isNull())
      return true;
    const CXXRecordDecl *Base = BaseType.getTypePtr()->getAsCXXRecordDecl();
    if (!Base)
      return true;
    DeclarationName DeclName = DepMemberRef->getMemberNameInfo().getName();
    if (!DeclName.isIdentifier())
      return true;
    StringRef DependentName = DeclName.getAsIdentifierInfo()->getName();

    if (NameLookup Resolved = findDeclInBases(
            *Base, DependentName, AggressiveDependentMemberLookup)) {
      if (*Resolved)
        Check->addUsage(*Resolved,
                        DepMemberRef->getMemberNameInfo().getSourceRange(), SM);
    }

    return true;
  }

  bool VisitTypedefTypeLoc(const TypedefTypeLoc &Loc) {
    Check->addUsage(Loc.getTypedefNameDecl(), Loc.getSourceRange(), SM);
    return true;
  }

  bool VisitTagTypeLoc(const TagTypeLoc &Loc) {
    Check->addUsage(Loc.getDecl(), Loc.getSourceRange(), SM);
    return true;
  }

  bool VisitInjectedClassNameTypeLoc(const InjectedClassNameTypeLoc &Loc) {
    Check->addUsage(Loc.getDecl(), Loc.getSourceRange(), SM);
    return true;
  }

  bool VisitUnresolvedUsingTypeLoc(const UnresolvedUsingTypeLoc &Loc) {
    Check->addUsage(Loc.getDecl(), Loc.getSourceRange(), SM);
    return true;
  }

  bool VisitTemplateTypeParmTypeLoc(const TemplateTypeParmTypeLoc &Loc) {
    Check->addUsage(Loc.getDecl(), Loc.getSourceRange(), SM);
    return true;
  }

  bool
  VisitTemplateSpecializationTypeLoc(const TemplateSpecializationTypeLoc &Loc) {
    const TemplateDecl *Decl =
        Loc.getTypePtr()->getTemplateName().getAsTemplateDecl();

    SourceRange Range(Loc.getTemplateNameLoc(), Loc.getTemplateNameLoc());
    if (const auto *ClassDecl = dyn_cast<TemplateDecl>(Decl)) {
      if (const NamedDecl *TemplDecl = ClassDecl->getTemplatedDecl())
        Check->addUsage(TemplDecl, Range, SM);
    }

    return true;
  }

  bool VisitDependentTemplateSpecializationTypeLoc(
      const DependentTemplateSpecializationTypeLoc &Loc) {
    if (const TagDecl *Decl = Loc.getTypePtr()->getAsTagDecl())
      Check->addUsage(Decl, Loc.getSourceRange(), SM);

    return true;
  }

  bool VisitDesignatedInitExpr(DesignatedInitExpr *Expr) {
    for (const DesignatedInitExpr::Designator &D : Expr->designators()) {
      if (!D.isFieldDesignator())
        continue;
      const FieldDecl *FD = D.getFieldDecl();
      if (!FD)
        continue;
      const IdentifierInfo *II = FD->getIdentifier();
      if (!II)
        continue;
      SourceRange FixLocation{D.getFieldLoc(), D.getFieldLoc()};
      Check->addUsage(FD, FixLocation, SM);
    }

    return true;
  }

private:
  RenamerClangTidyCheck *Check;
  const SourceManager &SM;
  const bool AggressiveDependentMemberLookup;
};

} // namespace

namespace clang::tidy {

int clangTidyMain(int argc, const char **argv) {
  auto CI = std::make_unique<CompilerInstance>();

  CI->createDiagnostics();

  llvm::IntrusiveRefCntPtr<vfs::OverlayFileSystem> BaseFS(
      new vfs::OverlayFileSystem(vfs::getRealFileSystem()));
  auto MemFS = llvm::IntrusiveRefCntPtr<vfs::InMemoryFileSystem>(
      new vfs::InMemoryFileSystem());
  BaseFS->pushOverlay(MemFS);

  if (!MemFS->addFile("test.cpp", 0,
                      llvm::MemoryBuffer::getMemBuffer(
                          R"cpp(
class Foo {
public:
  Foo() = default;
private:
  int bar_;
};
)cpp",
                          "test.cpp"))) {
    throw std::exception("");
  };
  auto &FileMgr = *CI->createFileManager(BaseFS);

  CI->createSourceManager(FileMgr);
  auto FileEntry = FileMgr.getFileRef("test.cpp");
  auto &SourceMgr = CI->getSourceManager();

  auto OwningOptionsProvider = createOptionsProvider(BaseFS);

  ClangTidyContext Context(std::move(OwningOptionsProvider), false, false);

  CI->getFrontendOpts().Inputs.emplace_back(
      FrontendInputFile("test.cpp", Language::CXX));

  auto imc = IdentifierNamingCheck("readability-identifier-naming", &Context);

  std::shared_ptr<clang::TargetOptions> to =
      std::make_shared<clang::TargetOptions>();
  to->Triple = "x86_64-pc-windows-msvc";
  CI->setTarget(clang::TargetInfo::CreateTargetInfo(CI->getDiagnostics(), to));

  if (FileEntry) {
    SourceMgr.setMainFileID(
        SourceMgr.createFileID(*FileEntry, SourceLocation(), SrcMgr::C_User));

    RenamerClangTidyVisitor Visitor(&imc, SourceMgr, true);
    auto AST = ASTUnit::LoadFromCompilerInvocation(
        CI->getInvocationPtr(), CI->getPCHContainerOperations(),
        CI->getDiagnosticsPtr(), &FileMgr);
    Visitor.TraverseAST(AST->getASTContext());
  }

  return 0;
}

} // namespace clang::tidy
