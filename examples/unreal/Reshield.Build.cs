// UNTESTED. This file was never built with Unreal Build Tool: no engine was available when it was
// written. Property names were checked against Epic's "Module Properties" page
// (https://dev.epicgames.com/documentation/en-us/unreal-engine/module-properties-in-unreal-engine);
// Target.Configuration and UnrealTargetConfiguration.Shipping are from general UE knowledge and were
// not confirmed on an official page. Treat it as a starting point and read docs/engines-unreal.md.
//
// Layout this template assumes (a source module that carries the re-shield C sources):
//   <Project>/Source/Reshield/Reshield.Build.cs                   this file
//   <Project>/Source/Reshield/ThirdParty/include/reshield/*.h     copy of include/reshield/
//   <Project>/Source/Reshield/Private/ThirdParty/src/*           copy of src/*.c and src/*.h
// Whether UBT compiles .c files is unconfirmed. If it does not, give each src/X.c a one-line
// X.cpp next to it that does #include "X.c" and remove the .c files from Private/.

using System.IO;
using UnrealBuildTool;

public class Reshield : ModuleRules
{
    public Reshield(ReadOnlyTargetRules Target) : base(Target)
    {
        Type = ModuleType.CPlusPlus;

        // src/attestation_windows.c and src/manifest.c each define `static int hex_nibble(char)`.
        // A unity build merges them into one translation unit and fails with a redefinition.
        bUseUnity = false;
        PCHUsage = PCHUsageMode.NoPCHs;

        // src/*.c include "reshield/..." headers.
        PublicIncludePaths.Add(Path.Combine(ModuleDirectory, "ThirdParty", "include"));

        // Core is only needed for the module boilerplate (IMPLEMENT_MODULE) and the caller's code.
        PublicDependencyModuleNames.Add("Core");

        // A sealed binary must come from a RELEASE build of re-shield: do not define
        // RESHIELD_ALLOW_UNSEALED for Shipping. tools/reshield_release.py refuses a binary that
        // contains the development marker RESHIELD-DEV-BUILD-v1.
        if (Target.Configuration != UnrealTargetConfiguration.Shipping)
        {
            PrivateDefinitions.Add("RESHIELD_ALLOW_UNSEALED");
        }

        // Optional: force the portable SHA-256 path instead of the SHA-NI intrinsics in
        // src/sha256_accel.c (only the MSVC cl and gcc/clang combinations were measured upstream).
        // PrivateDefinitions.Add("RESHIELD_NO_HW_SHA");

        // wintrust.lib and psapi.lib are linked by #pragma comment in src/attestation_windows.c.
        // Whether UBT's link step honors that pragma was not checked; if the link fails with
        // unresolved WinVerifyTrust/GetMappedFileNameW, add them with PublicSystemLibraries.
    }
}
