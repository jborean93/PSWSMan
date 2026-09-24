using System;
using System.Collections.Generic;
using System.Management.Automation.Runspaces;
using System.Runtime.CompilerServices;
using System.Threading;

namespace PSWSMan;

internal class RunspaceSpecificStorage<T>
{
    private readonly ConditionalWeakTable<Runspace, Lazy<T>> _map = [];

    private readonly Func<T> _factory;

    private readonly LazyThreadSafetyMode _mode = LazyThreadSafetyMode.ExecutionAndPublication;

    private readonly Lazy<T> _noRunspace;

    public RunspaceSpecificStorage(Func<T> factory)
    {
        _factory = factory;
        _noRunspace = new Lazy<T>(() => _factory(), _mode);
    }

    /// <summary>Gets the value for the runspace of the current thread.</summary>
    /// <remarks>
    /// A thread with no default runspace, such as a host opening a runspace from a thread pool thread, has no
    /// runspace whose settings could have been configured so it shares a single instance holding the defaults.
    /// </remarks>
    public T GetFromTLS()
    {
        Runspace? runspace = Runspace.DefaultRunspace;
        return runspace is null ? _noRunspace.Value : GetForRunspace(runspace);
    }

    public T GetForRunspace(Runspace runspace)
    {
        return _map.GetValue(
            runspace,
            _ => new Lazy<T>(() => _factory(), _mode))
            .Value;
    }
}

/// <summary>
/// Stores the module-specific settings for the current runspace.
/// </summary>
internal class ModuleSettings
{
    public const string DefaultGssapiLib = "Default";

    private static readonly RunspaceSpecificStorage<ModuleSettings> _state = new(() => new());

    private ModuleSettings() { }

    /// <summary>The default authentication provider set for the module.</summary>
    public AuthenticationProvider DefaultAuthProvider { get; set; } = AuthenticationProvider.System;

    /// <summary>The path to the GSSAPI library used by the module, <c>Default</c> means the pre-defined library is used.</summary>
    public string GssapiLib { get; set; } = DefaultGssapiLib;

    public static ModuleSettings GetFromTLS() => _state.GetFromTLS();
}
