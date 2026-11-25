// UNTESTED in Unity: never compiled or run in a Unity Editor. Excluded from the dotnet build
// (UNITY_5_3_OR_NEWER guard); only Reshield.cs is compile-checked there.
#if UNITY_5_3_OR_NEWER
using System;
using System.Threading;
using UnityEngine;

namespace Reshield
{
    /// <summary>
    /// Runs the re-shield startup check once, on a background thread, and reports the result on the
    /// main thread. Report-only: it never quits the game, throws, or blocks a frame. Use OnResult to
    /// mark the session or send telemetry; let a server decide (docs/engines-unity.md).
    /// </summary>
    public sealed class ReshieldGuard : MonoBehaviour
    {
        [Tooltip("Sealed manifest, relative to the player executable's folder. Empty = code check only.")]
        public string manifestPath = "";

        [Tooltip("Asset base directory the manifest paths are relative to, same base. Empty = \".\".")]
        public string assetsPath = "";

        [Tooltip("The Editor and development builds are not sealed: skip the check there.")]
        public bool skipInEditorAndDevelopmentBuilds = true;

        /// <summary>Raised on the main thread, once. Do not quit the game from here (see the docs).</summary>
        public event Action<CheckResult> OnResult;

        public CheckResult LastResult { get; private set; }

        private volatile CheckResult _pending;

        private void Start()
        {
            if (skipInEditorAndDevelopmentBuilds && (Application.isEditor || Debug.isDebugBuild))
            {
                Debug.Log("[re-shield] skipped (editor or development build)");
                return;
            }
            string manifest = string.IsNullOrEmpty(manifestPath) ? null : manifestPath;
            string assets = string.IsNullOrEmpty(assetsPath) ? null : assetsPath;
            // Own thread, not the pool: the check blocks for up to a second on a big GameAssembly.
            var t = new Thread(() => _pending = Guard.Check(manifest, assets))
            {
                IsBackground = true,
                Name = "reshield-check"
            };
            t.Start();
        }

        private void Update()
        {
            CheckResult r = _pending;
            if (r == null) return;
            _pending = null;
            LastResult = r;
            if (r.Ok) Debug.Log("[re-shield] OK");
            else Debug.LogWarning("[re-shield] " + r.StatusName + " " + r.Json);
            OnResult?.Invoke(r);
        }
    }
}
#endif
