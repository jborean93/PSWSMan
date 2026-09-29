using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Runspaces;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan;

/// <summary>The connection options of the PSWSMan WinRM cmdlets.</summary>
/// <remarks>
/// Unlike <see cref="PSSessionOption"/> this only has the settings PSWSMan's own client honours, anything else
/// cannot be set rather than being silently ignored. The WinRM and WinRS cmdlets take it through
/// <see cref="WinRMSessionOptionTransformAttribute"/> so a PSSessionOption or a hashtable works as well.
/// </remarks>
public sealed class WinRMSessionOption
{
    /// <summary>The ETS member of a converted PSSessionOption that holds the options it was converted from.</summary>
    internal const string PSSessionOptionProperty = "_WinRMSessionOption";

    public TimeSpan OpenTimeout { get; set; } = TimeSpan.FromMinutes(3);

    public TimeSpan OperationTimeout { get; set; } = TimeSpan.FromMinutes(3);

    public TimeSpan CancelTimeout { get; set; } = TimeSpan.FromMinutes(1);

    public int MaxConnectionRetryCount { get; set; } = 5;

    public CultureInfo? Culture { get; set; }

    public CultureInfo? UICulture { get; set; }

    public bool NoMachineProfile { get; set; }

    public PSPrimitiveDictionary? ApplicationArguments { get; set; }

    public bool SkipCACheck { get; set; }

    public bool SkipCNCheck { get; set; }

    public bool NoEncryption { get; set; }

    public AuthenticationMethod AuthMethod { get; set; } = AuthenticationMethod.Default;

    public AuthenticationProvider AuthProvider { get; set; } = AuthenticationProvider.Default;

    public string? SPNService { get; set; }

    public string? SPNHostName { get; set; }

    public bool RequestKerberosDelegate { get; set; }

    public X509Certificate? ClientCertificate { get; set; }

    public SslClientAuthenticationOptions? TlsOption { get; set; }

    public AuthenticationMethod CredSSPAuthMethod { get; set; } = AuthenticationMethod.Default;

    public SslClientAuthenticationOptions? CredSSPTlsOption { get; set; }

    /// <summary>A file the connection's diagnostic messages are appended to.</summary>
    /// <remarks>
    /// Only New-WinRMSession and the WinRS cmdlets use it, the builtin remoting cmdlets write to the ClientTransport
    /// trace source instead.
    /// </remarks>
    public string? TracePath { get; set; }

    /// <summary>A copy with a relative TracePath resolved against the current PowerShell location.</summary>
    internal WinRMSessionOption ResolveTracePath(SessionState sessionState)
    {
        if (string.IsNullOrWhiteSpace(TracePath))
        {
            return this;
        }

        WinRMSessionOption copy = (WinRMSessionOption)MemberwiseClone();
        copy.TracePath = sessionState.Path.GetUnresolvedProviderPathFromPSPath(TracePath);
        return copy;
    }

    /// <summary>Converts the options for the builtin remoting cmdlets like New-PSSession and Invoke-Command.</summary>
    /// <remarks>
    /// The options PSSessionOption has no property for are kept by attaching a copy of this object as an ETS member,
    /// the patched transport reads them once Enable-PSWSMan has been run. PowerShell uses this conversion when the options are
    /// passed to a -SessionOption typed as PSSessionOption or set as $PSSessionOption.
    /// </remarks>
    public static implicit operator PSSessionOption(WinRMSessionOption option) => option.ToPSSessionOption();

    /// <summary>Creates a PSSessionOption with these options for the builtin remoting cmdlets.</summary>
    public PSSessionOption ToPSSessionOption()
    {
        PSSessionOption result = new()
        {
            OpenTimeout = OpenTimeout,
            OperationTimeout = OperationTimeout,
            CancelTimeout = CancelTimeout,
            MaxConnectionRetryCount = MaxConnectionRetryCount,
            Culture = Culture,
            UICulture = UICulture,
            NoMachineProfile = NoMachineProfile,
            ApplicationArguments = ApplicationArguments,
            SkipCACheck = SkipCACheck,
            SkipCNCheck = SkipCNCheck,
            NoEncryption = NoEncryption,
        };
        // A copy so changing this object later does not change the PSSessionOption.
        PSObject.AsPSObject(result).Properties.Add(new PSNoteProperty(PSSessionOptionProperty,
            (WinRMSessionOption)MemberwiseClone()));

        return result;
    }

    /// <summary>Builds the options for a PSSessionOption, including those attached by the conversion to it.</summary>
    /// <remarks>
    /// The PSSessionOption properties win over the attached options so a change made to them after the conversion
    /// is kept.
    /// </remarks>
    /// <exception cref="ArgumentException">The PSSessionOption sets something PSWSMan cannot honour.</exception>
    internal static WinRMSessionOption FromPSSessionOption(PSSessionOption source)
    {
        PSSessionOption defaults = new();
        List<string> unsupported = new();
        void Check(string name, object? value, object? defaultValue)
        {
            if (!Equals(value, defaultValue))
            {
                unsupported.Add(name);
            }
        }
        Check(nameof(PSSessionOption.MaximumConnectionRedirectionCount), source.MaximumConnectionRedirectionCount,
            defaults.MaximumConnectionRedirectionCount);
        Check(nameof(PSSessionOption.NoCompression), source.NoCompression, defaults.NoCompression);
        Check(nameof(PSSessionOption.ProxyAccessType), source.ProxyAccessType, defaults.ProxyAccessType);
        Check(nameof(PSSessionOption.ProxyAuthentication), source.ProxyAuthentication, defaults.ProxyAuthentication);
        Check(nameof(PSSessionOption.ProxyCredential), source.ProxyCredential, defaults.ProxyCredential);
        Check(nameof(PSSessionOption.SkipRevocationCheck), source.SkipRevocationCheck, defaults.SkipRevocationCheck);
        Check(nameof(PSSessionOption.UseUTF16), source.UseUTF16, defaults.UseUTF16);
        Check(nameof(PSSessionOption.IncludePortInSPN), source.IncludePortInSPN, defaults.IncludePortInSPN);
        Check(nameof(PSSessionOption.OutputBufferingMode), source.OutputBufferingMode, defaults.OutputBufferingMode);
        Check(nameof(PSSessionOption.IdleTimeout), source.IdleTimeout, defaults.IdleTimeout);
        Check(nameof(PSSessionOption.MaximumReceivedDataSizePerCommand), source.MaximumReceivedDataSizePerCommand,
            defaults.MaximumReceivedDataSizePerCommand);
        // New-PSSessionOption on Windows always assigns its parameter, which is null when not given, while the class
        // defaults to 200MiB. Both mean it was left alone.
        if (source.MaximumReceivedObjectSize is not null)
        {
            Check(nameof(PSSessionOption.MaximumReceivedObjectSize), source.MaximumReceivedObjectSize,
                defaults.MaximumReceivedObjectSize);
        }
        if (unsupported.Count > 0)
        {
            throw new ArgumentException(
                $"The PSSessionOption sets {string.Join(", ", unsupported)} which PSWSMan does not support. " +
                "Use New-WinRMSessionOption to see the options that are available.");
        }

        WinRMSessionOption result = new()
        {
            OpenTimeout = source.OpenTimeout,
            OperationTimeout = source.OperationTimeout,
            CancelTimeout = source.CancelTimeout,
            MaxConnectionRetryCount = source.MaxConnectionRetryCount,
            Culture = source.Culture,
            UICulture = source.UICulture,
            NoMachineProfile = source.NoMachineProfile,
            ApplicationArguments = source.ApplicationArguments,
            SkipCACheck = source.SkipCACheck,
            SkipCNCheck = source.SkipCNCheck,
            NoEncryption = source.NoEncryption,
        };
        result.ApplyExtras(GetExtraOptions(source));

        return result;
    }

    /// <summary>Builds the options the patched PowerShell transport was given.</summary>
    /// <remarks>
    /// This is the built-in remoting path so settings PSWSMan does not support are ignored as they always have been.
    /// An authentication mechanism set on the connection takes precedence over the AuthMethod of the options.
    /// </remarks>
    internal static WinRMSessionOption FromConnectionInfo(WSManConnectionInfo connInfo)
    {
        WinRMSessionOption result = new()
        {
            OpenTimeout = TimeSpan.FromMilliseconds(connInfo.OpenTimeout),
            OperationTimeout = TimeSpan.FromMilliseconds(connInfo.OperationTimeout),
            CancelTimeout = TimeSpan.FromMilliseconds(connInfo.CancelTimeout),
            MaxConnectionRetryCount = connInfo.MaxConnectionRetryCount,
            Culture = connInfo.Culture,
            UICulture = connInfo.UICulture,
            NoMachineProfile = connInfo.NoMachineProfile,
            SkipCACheck = connInfo.SkipCACheck,
            SkipCNCheck = connInfo.SkipCNCheck,
            NoEncryption = connInfo.NoEncryption,
        };
        result.ApplyExtras(GetExtraOptions(connInfo));

        // An explicit -Authentication wins over the AuthMethod of the options, the same as the PSWSMan cmdlets.
        AuthenticationMethod explicitMethod = connInfo.AuthenticationMechanism switch
        {
            AuthenticationMechanism.Basic => AuthenticationMethod.Basic,
            AuthenticationMechanism.Credssp => AuthenticationMethod.CredSSP,
            AuthenticationMechanism.Kerberos => AuthenticationMethod.Kerberos,
            AuthenticationMechanism.Negotiate => AuthenticationMethod.Negotiate,
            AuthenticationMechanism.NegotiateWithImplicitCredential => AuthenticationMethod.Negotiate,
            _ => AuthenticationMethod.Default,
        };
        if (explicitMethod != AuthenticationMethod.Default)
        {
            result.AuthMethod = explicitMethod;
        }

        return result;
    }

    /// <summary>Builds the options from a hashtable whose keys are the property names.</summary>
    /// <remarks>
    /// A timeout given as a number is in milliseconds, the same as the timeout parameters of
    /// New-WinRMSessionOption and New-PSSessionOption, rather than the ticks a TimeSpan conversion would use.
    /// </remarks>
    /// <exception cref="ArgumentException">A key is not an option or its value cannot be converted.</exception>
    internal static WinRMSessionOption FromDictionary(IDictionary source)
    {
        WinRMSessionOption result = new();
        foreach (DictionaryEntry entry in source)
        {
            string key = entry.Key?.ToString() ?? "";
            PropertyInfo? prop = typeof(WinRMSessionOption).GetProperty(key,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
            if (prop is null)
            {
                string valid = string.Join(", ", Array.ConvertAll(
                    typeof(WinRMSessionOption).GetProperties(BindingFlags.Instance | BindingFlags.Public),
                    p => p.Name));
                throw new ArgumentException($"'{key}' is not a WinRM session option, valid options are {valid}.");
            }

            object? value = entry.Value is PSObject psObj ? psObj.BaseObject : entry.Value;
            if (prop.PropertyType == typeof(TimeSpan) && value is not null and not TimeSpan &&
                (value is not string raw || double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out _)))
            {
                value = TimeSpan.FromMilliseconds((double)LanguagePrimitives.ConvertTo(value, typeof(double),
                    CultureInfo.InvariantCulture));
            }

            try
            {
                prop.SetValue(result, LanguagePrimitives.ConvertTo(value, prop.PropertyType,
                    CultureInfo.InvariantCulture));
            }
            catch (PSInvalidCastException e)
            {
                throw new ArgumentException($"The value for WinRM session option '{prop.Name}' is not valid: " +
                    e.Message, e);
            }
        }

        return result;
    }

    private static WinRMSessionOption? GetExtraOptions(object source)
    {
        return PSObject.AsPSObject(source)
            .Properties[PSSessionOptionProperty]
            ?.Value as WinRMSessionOption;
    }

    /// <summary>Copies the options PSSessionOption has no property for.</summary>
    private void ApplyExtras(WinRMSessionOption? extras)
    {
        if (extras is null)
        {
            return;
        }

        AuthMethod = extras.AuthMethod;
        AuthProvider = extras.AuthProvider;
        SPNService = extras.SPNService;
        SPNHostName = extras.SPNHostName;
        RequestKerberosDelegate = extras.RequestKerberosDelegate;
        ClientCertificate = extras.ClientCertificate;
        TlsOption = extras.TlsOption;
        CredSSPAuthMethod = extras.CredSSPAuthMethod;
        CredSSPTlsOption = extras.CredSSPTlsOption;
        TracePath = extras.TracePath;
    }
}

/// <summary>Accepts a WinRMSessionOption, a PSSessionOption or a hashtable of options for -SessionOption.</summary>
public sealed class WinRMSessionOptionTransformAttribute : ArgumentTransformationAttribute
{
    public override object? Transform(EngineIntrinsics engineIntrinsics, object? inputData)
    {
        object? value = inputData is PSObject psObj ? psObj.BaseObject : inputData;
        try
        {
            return value switch
            {
                null => null,
                WinRMSessionOption option => option,
                PSSessionOption => WinRMSessionOption.FromPSSessionOption((PSSessionOption)value),
                IDictionary dict => WinRMSessionOption.FromDictionary(dict),
                _ => throw new ArgumentException(
                    $"Cannot convert '{value.GetType().FullName}' to a WinRM session option, use the output of " +
                    "New-WinRMSessionOption, New-PSSessionOption or a hashtable."),
            };
        }
        catch (ArgumentException e)
        {
            throw new ArgumentTransformationMetadataException(e.Message, e);
        }
    }
}
