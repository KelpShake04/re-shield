// re-shield C# binding: P/Invoke of the flat C functions only (no struct is mirrored, so a report
// layout change never breaks this file). Works in plain .NET and in Unity (Mono and IL2CPP).
//
// Library name: "reshield" (the runtime adds the platform prefix/suffix: reshield.dll,
// libreshield.so, libreshield.dylib). Define RESHIELD_INTERNAL when the C sources are compiled into
// the player itself (Unity IL2CPP source plugin): the symbols are then resolved from the main
// program as "__Internal".
//
// Runtime policy: Check() never throws. If the native module cannot be loaded or lacks the entry
// point, it returns Status = ModuleNotFound (-1). That is a deployment or environment problem, not
// evidence of tampering: treat it as FAIL-OPEN (let the game run, log it, send verified=false).
// Build-time problems are the opposite and belong to tools/reshield_release.py (fail-closed).
//
// Threading: Check() blocks while it hashes the code section (about 0.1-0.5 s for a large
// GameAssembly) and keeps no global state in this file, so call it from a worker thread, not the
// main/render thread.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Reshield
{
    public sealed class CheckResult
    {
        /// <summary>reshield_status_t value (0 = OK), or Guard.ModuleNotFound (-1).</summary>
        public int Status { get; }
        public string StatusName { get; }
        /// <summary>One-line JSON report (schema "v":1). An unauthenticated client claim.</summary>
        public string Json { get; }
        public bool Ok => Status == 0;

        public CheckResult(int status, string statusName, string json)
        {
            Status = status;
            StatusName = statusName;
            Json = json;
        }
    }

    public static class Guard
    {
        public const int ModuleNotFound = -1;

#if RESHIELD_INTERNAL
        internal const string LibraryName = "__Internal";
#else
        internal const string LibraryName = "reshield";
#endif

        // Fixed output buffer for the JSON report (about 300 bytes in practice); longer output is
        // truncated safely by the native side.
        private const int JsonCapacity = 4096;

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int reshield_check_json(byte[] manifestRel, byte[] assetsRel,
                                                       byte[] json, UIntPtr cap);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr reshield_status_name(int status);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr reshield_platform_name();

        /// <summary>
        /// One-call startup check (code section + page permissions, plus the manifest when
        /// manifestRel is not null). Both paths are relative to the running executable's directory.
        /// Never throws; see the file header for the fail-open rule.
        /// </summary>
        public static CheckResult Check(string manifestRel = null, string assetsRel = null)
        {
            try
            {
                byte[] buf = new byte[JsonCapacity];
                int status = reshield_check_json(ToCString(manifestRel), ToCString(assetsRel),
                                                 buf, (UIntPtr)buf.Length);
                int len = Array.IndexOf(buf, (byte)0);
                string json = Encoding.UTF8.GetString(buf, 0, len < 0 ? buf.Length : len);
                return new CheckResult(status, ReadCString(reshield_status_name(status)), json);
            }
            catch (Exception e) when (IsNoModule(e))
            {
                return new CheckResult(ModuleNotFound, "MODULE_NOT_FOUND",
                    "{\"v\":1,\"status\":\"MODULE_NOT_FOUND\",\"status_code\":-1,\"error\":\""
                    + e.GetType().Name + "\"}");
            }
        }

        /// <summary>Native platform backend name ("macos", "linux", "windows"), or null if no module.</summary>
        public static string PlatformName()
        {
            try { return ReadCString(reshield_platform_name()); }
            catch (Exception e) when (IsNoModule(e)) { return null; }
        }

        // BadImageFormat = plugin built for the wrong architecture: also "no usable module".
        private static bool IsNoModule(Exception e)
        {
            return e is DllNotFoundException || e is EntryPointNotFoundException
                   || e is BadImageFormatException;
        }

        private static byte[] ToCString(string s)
        {
            if (s == null) return null;
            byte[] utf8 = Encoding.UTF8.GetBytes(s);
            byte[] z = new byte[utf8.Length + 1]; // last byte stays 0 = NUL terminator
            Buffer.BlockCopy(utf8, 0, z, 0, utf8.Length);
            return z;
        }

        // Marshal.PtrToStringUTF8 does not exist on older Unity runtimes: read the bytes ourselves.
        private static string ReadCString(IntPtr p)
        {
            if (p == IntPtr.Zero) return null;
            int n = 0;
            while (Marshal.ReadByte(p, n) != 0) n++;
            byte[] b = new byte[n];
            Marshal.Copy(p, b, 0, n);
            return Encoding.UTF8.GetString(b);
        }
    }
}
