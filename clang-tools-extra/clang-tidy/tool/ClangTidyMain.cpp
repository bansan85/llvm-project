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

#if 0

static cl::desc desc(StringRef description) { return {description.ltrim()}; }

static cl::OptionCategory ClangTidyCategory("clang-tidy options");

static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp ClangTidyHelp(R"(
Configuration files:
  clang-tidy attempts to read configuration for each source file from a
  .clang-tidy file located in the closest parent directory of the source
  file. The .clang-tidy file is specified in YAML format. If any configuration
  options have a corresponding command-line option, command-line option takes
  precedence.

  The following configuration options may be used in a .clang-tidy file:

  CheckOptions                 - List of key-value pairs defining check-specific
                                 options. Example:
                                   CheckOptions:
                                     some-check.SomeOption: 'some value'
  Checks                       - Same as '--checks'. Additionally, the list of
                                 globs can be specified as a list instead of a
                                 string.
  ExcludeHeaderFilterRegex     - Same as '--exclude-header-filter'.
  ExtraArgs                    - Same as '--extra-args'.
  ExtraArgsBefore              - Same as '--extra-args-before'.
  FormatStyle                  - Same as '--format-style'.
  HeaderFileExtensions         - File extensions to consider to determine if a
                                 given diagnostic is located in a header file.
  HeaderFilterRegex            - Same as '--header-filter-regex'.
  ImplementationFileExtensions - File extensions to consider to determine if a
                                 given diagnostic is located in an
                                 implementation file.
  InheritParentConfig          - If this option is true in a config file, the
                                 configuration file in the parent directory
                                 (if any exists) will be taken and the current
                                 config file will be applied on top of the
                                 parent one.
  SystemHeaders                - Same as '--system-headers'.
  User                         - Specifies the name or e-mail of the user
                                 running clang-tidy. This option is used, for
                                 example, to place the correct user name in
                                 TODO() comments in the relevant check.
  WarningsAsErrors             - Same as '--warnings-as-errors'.

  The effective configuration can be inspected using --dump-config:

    $ clang-tidy --dump-config
    ---
    Checks:                       '-*,some-check'
    WarningsAsErrors:             ''
    HeaderFileExtensions:         ['', 'h','hh','hpp','hxx']
    ImplementationFileExtensions: ['c','cc','cpp','cxx']
    HeaderFilterRegex:            ''
    FormatStyle:                  none
    InheritParentConfig:          true
    User:                         user
    CheckOptions:
      some-check.SomeOption: 'some value'
    ...

)");

static cl::opt<std::string> Checks("checks", desc(R"(
Comma-separated list of globs with optional '-'
prefix. Globs are processed in order of
appearance in the list. Globs without '-'
prefix add checks with matching names to the
set, globs with the '-' prefix remove checks
with matching names from the set of enabled
checks. This option's value is appended to the
value of the 'Checks' option in .clang-tidy
file, if any.
)"),
                                   cl::init(""), cl::cat(ClangTidyCategory));

static cl::opt<bool> Fix("fix", desc(R"(
Apply suggested fixes. Without -fix-errors
clang-tidy will bail out if any compilation
errors were found.
)"),
                         cl::init(false), cl::cat(ClangTidyCategory));

static cl::opt<bool> FixErrors("fix-errors", desc(R"(
Apply suggested fixes even if compilation
errors were found. If compiler errors have
attached fix-its, clang-tidy will apply them as
well.
)"),
                               cl::init(false), cl::cat(ClangTidyCategory));

static cl::opt<bool> FixNotes("fix-notes", desc(R"(
If a warning has no fix, but a single fix can
be found through an associated diagnostic note,
apply the fix.
Specifying this flag will implicitly enable the
'--fix' flag.
)"),
                              cl::init(false), cl::cat(ClangTidyCategory));

static cl::opt<std::string> Config("config", desc(R"(
Specifies a configuration in YAML/JSON format:
  -config="{Checks: '*',
            CheckOptions: {x: y}}"
When the value is empty, clang-tidy will
attempt to find a file named .clang-tidy for
each source file in its parent directories.
)"),
                                   cl::init(""), cl::cat(ClangTidyCategory));

static cl::opt<std::string> StoreCheckProfile("store-check-profile", desc(R"(
By default reports are printed in tabulated
format to stderr. When this option is passed,
these per-TU profiles are instead stored as JSON.
)"),
                                              cl::value_desc("prefix"),
                                              cl::cat(ClangTidyCategory));

namespace clang::tidy {

static std::unique_ptr<ClangTidyOptionsProvider>
createOptionsProvider(llvm::IntrusiveRefCntPtr<vfs::FileSystem> FS) {
  ClangTidyGlobalOptions GlobalOptions;

  ClangTidyOptions DefaultOptions;
  DefaultOptions.Checks = Checks;
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
      parseConfiguration(MemoryBufferRef(Config, "<command-line-config>"));
  if (ParsedConfig)
    return std::make_unique<ConfigOptionsProvider>(
        std::move(GlobalOptions),
        ClangTidyOptions::getDefaults().merge(DefaultOptions, 0),
        std::move(*ParsedConfig), std::move(OverrideOptions), std::move(FS));
  llvm::errs() << "Error: invalid configuration specified.\n"
               << ParsedConfig.getError().message() << "\n";
  return nullptr;
}

llvm::IntrusiveRefCntPtr<vfs::FileSystem>
getVfsFromFile(const std::string &OverlayFile,
               llvm::IntrusiveRefCntPtr<vfs::FileSystem> BaseFS) {
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> Buffer =
      BaseFS->getBufferForFile(OverlayFile);
  if (!Buffer) {
    llvm::errs() << "Can't load virtual filesystem overlay file '"
                 << OverlayFile << "': " << Buffer.getError().message()
                 << ".\n";
    return nullptr;
  }

  IntrusiveRefCntPtr<vfs::FileSystem> FS = vfs::getVFSFromYAML(
      std::move(Buffer.get()), /*DiagHandler*/ nullptr, OverlayFile);
  if (!FS) {
    llvm::errs() << "Error: invalid virtual filesystem overlay file '"
                 << OverlayFile << "'.\n";
    return nullptr;
  }
  return FS;
}

static constexpr StringLiteral VerifyConfigWarningEnd = " [-verify-config]\n";

static SmallString<256> makeAbsolute(llvm::StringRef Input) {
  if (Input.empty())
    return {};
  SmallString<256> AbsolutePath(Input);
  if (std::error_code EC = llvm::sys::fs::make_absolute(AbsolutePath)) {
    llvm::errs() << "Can't make absolute path from " << Input << ": "
                 << EC.message() << "\n";
  }
  return AbsolutePath;
}

static llvm::IntrusiveRefCntPtr<vfs::OverlayFileSystem> createBaseFS() {
  llvm::IntrusiveRefCntPtr<vfs::OverlayFileSystem> BaseFS(
      new vfs::OverlayFileSystem(vfs::getRealFileSystem()));

  return BaseFS;
}

int clangTidyMain(int argc, const char **argv) {
  llvm::Expected<CommonOptionsParser> OptionsParser =
      CommonOptionsParser::create(argc, argv, ClangTidyCategory,
                                  cl::ZeroOrMore);
  if (!OptionsParser) {
    llvm::WithColor::error() << llvm::toString(OptionsParser.takeError());
    return 1;
  }

  llvm::IntrusiveRefCntPtr<vfs::OverlayFileSystem> BaseFS = createBaseFS();
  if (!BaseFS)
    return 1;

  auto OwningOptionsProvider = createOptionsProvider(BaseFS);
  auto *OptionsProvider = OwningOptionsProvider.get();
  if (!OptionsProvider)
    return 1;

  SmallString<256> ProfilePrefix = makeAbsolute(StoreCheckProfile);

  StringRef FileName("dummy");
  auto PathList = OptionsParser->getSourcePathList();
  if (!PathList.empty()) {
    FileName = PathList.front();
  }

  SmallString<256> FilePath = makeAbsolute(FileName);
  ClangTidyOptions EffectiveOptions = OptionsProvider->getOptions(FilePath);

  std::vector<std::string> EnabledChecks =
      getCheckNames(EffectiveOptions, false);

  if (EnabledChecks.empty()) {
    llvm::errs() << "Error: no checks enabled.\n";
    llvm::cl::PrintHelpMessage(/*Hidden=*/false, /*Categorized=*/true);
    return 1;
  }

  if (PathList.empty()) {
    llvm::errs() << "Error: no input files specified.\n";
    llvm::cl::PrintHelpMessage(/*Hidden=*/false, /*Categorized=*/true);
    return 1;
  }

  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();

  ClangTidyContext Context(std::move(OwningOptionsProvider), false, false);
  std::vector<ClangTidyError> Errors =
      runClangTidy(Context, OptionsParser->getCompilations(), PathList, BaseFS,
                   FixNotes, false, ProfilePrefix);
  bool FoundErrors = llvm::any_of(Errors, [](const ClangTidyError &E) {
    return E.DiagLevel == ClangTidyError::Error;
  });

  // --fix-errors and --fix-notes imply --fix.
  FixBehaviour Behaviour = FixNotes             ? FB_FixNotes
                           : (Fix || FixErrors) ? FB_Fix
                                                : FB_NoFix;

  const bool DisableFixes = FoundErrors && !FixErrors;

  unsigned WErrorCount = 0;

  handleErrors(Errors, Context, DisableFixes ? FB_NoFix : Behaviour,
               WErrorCount, BaseFS);

  if (FoundErrors) {
    // TODO: Figure out when zero exit code should be used with -fix-errors:
    //   a. when a fix has been applied for an error
    //   b. when a fix has been applied for all errors
    //   c. some other condition.
    // For now always returning zero when -fix-errors is used.
    if (FixErrors)
      return 0;
    return 1;
  }

  return 0;
}

} // namespace clang::tidy

#endif

#if 1

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

static llvm::IntrusiveRefCntPtr<vfs::OverlayFileSystem> createBaseFS() {
  llvm::IntrusiveRefCntPtr<vfs::OverlayFileSystem> BaseFS(
      new vfs::OverlayFileSystem(vfs::getRealFileSystem()));

  return BaseFS;
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
  llvm::IntrusiveRefCntPtr<vfs::OverlayFileSystem> BaseFS = createBaseFS();

  auto MemFS = llvm::IntrusiveRefCntPtr<vfs::InMemoryFileSystem>(
      new vfs::InMemoryFileSystem());
  MemFS->addFile("test.cpp", 0,
                 llvm::MemoryBuffer::getMemBuffer(
                     R"cpp(
class Foo {
public:
  Foo() = default;
private:
  int bar_;
};
)cpp"));
  BaseFS->pushOverlay(MemFS);

  auto OwningOptionsProvider = createOptionsProvider(BaseFS);

  ClangTidyContext Context(std::move(OwningOptionsProvider), false, false);

  auto imc = IdentifierNamingCheck("readability-identifier-naming", &Context);

  auto CI = std::make_unique<CompilerInstance>();
  CI->createDiagnostics();
  CI->createFileManager(MemFS);
  CI->createSourceManager(CI->getFileManager());
  auto &FileMgr = CI->getFileManager();
  auto &SourceMgr = CI->getSourceManager();
  /*
  SourceMgr.setDiagnostics(CI->getDiagnostics());
  SourceMgr.setFileManager(FileMgr);
  SourceMgr.setVirtualFileSystem(BaseFS);
  */
  auto FileEntry = FileMgr.getFileRef("test.cpp");
  SourceMgr.setMainFileID(
      SourceMgr.createFileID(*FileEntry, SourceLocation(), SrcMgr::C_User));

  RenamerClangTidyVisitor Visitor(&imc, SourceMgr, true);
  auto AST = ASTUnit::LoadFromCompilerInvocation(
      CI->getInvocationPtr(), CI->getPCHContainerOperations(),
      CI->getDiagnosticsPtr(), &FileMgr);
  Visitor.TraverseAST(AST->getASTContext());

  return 0;
}

} // namespace clang::tidy

#endif