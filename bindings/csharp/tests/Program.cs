// One scenario per process (a DllImport binding is resolved once and cached per process).
// usage: <library path | none> <expected status> <expected status name>
//        [<manifest rel> <assets rel> <asset rel> <max bytes> <expected asset status> <expected text | ->]
// With the second group it also calls Guard.LoadAsset (paths relative to the dotnet host's directory).
// run.py builds the libraries and starts one process per scenario.
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 3 && args.Length != 9)
        { Console.Error.WriteLine("usage: <lib path|none> <status> <name> [<manifest> <assets> <asset> <max> <status> <text|->]"); return 2; }
        string lib = args[0];
        int wantStatus = int.Parse(args[1]);
        string wantName = args[2];

        // Point the "reshield" import at the library under test; "none" leaves default probing, which
        // finds nothing next to the test binary.
        NativeLibrary.SetDllImportResolver(typeof(Reshield.Guard).Assembly,
            (name, asm, path) => name == "reshield" && lib != "none"
                ? NativeLibrary.Load(lib) : IntPtr.Zero);

        // From a worker thread, as the docs recommend. The host (dotnet) is never sealed.
        Reshield.CheckResult r = Task.Run(() => Reshield.Guard.Check()).GetAwaiter().GetResult();
        Console.WriteLine($"status={r.Status} name={r.StatusName} json={r.Json}");

        if (r.Status != wantStatus) return Fail($"status {r.Status}, want {wantStatus}");
        if (r.StatusName != wantName) return Fail($"name {r.StatusName}, want {wantName}");
        if (!r.Json.Contains($"\"status\":\"{wantName}\"") || !r.Json.StartsWith("{\"v\":1"))
            return Fail("json does not carry the status name");
        if (r.Ok != (wantStatus == 0)) return Fail("Ok flag");

        string plat = Reshield.Guard.PlatformName();
        if (wantStatus == Reshield.Guard.ModuleNotFound)
        {
            if (plat != null) return Fail("PlatformName must be null without a module");
        }
        else if (string.IsNullOrEmpty(plat)) return Fail("PlatformName empty");

        if (args.Length == 9)
        {
            int wantAsset = int.Parse(args[7]);
            Reshield.AssetResult a = Task.Run(() => Reshield.Guard.LoadAsset(args[3], args[4], args[5],
                int.Parse(args[6]))).GetAwaiter().GetResult();
            Console.WriteLine($"asset status={a.Status} name={a.StatusName} bytes={(a.Data == null ? -1 : a.Data.Length)}");
            if (a.Status != wantAsset) return Fail($"asset status {a.Status}, want {wantAsset}");
            if (a.Ok != (wantAsset == 0)) return Fail("asset Ok flag");
            if (a.Ok)
            {
                if (a.Data == null || System.Text.Encoding.UTF8.GetString(a.Data) != args[8])
                    return Fail("asset bytes differ from the expected text");
            }
            else if (a.Data != null) return Fail("Data must be null unless Ok");
        }

        Console.WriteLine("PASS");
        return 0;
    }

    private static int Fail(string why) { Console.Error.WriteLine("FAIL: " + why); return 1; }
}
