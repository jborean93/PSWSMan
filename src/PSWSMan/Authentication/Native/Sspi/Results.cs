namespace PSWSMan.Authentication.Native;

/// <summary>Result of <c>InitializeSecurityContext</c>.</summary>
internal class SspiSecContext
{
    /// <summary>The handle to the SSPI security context.</summary>
    public SafeSspiContextHandle Context { get; }

    /// <summary>The attributes used to describe the functionality available on the context.</summary>
    public InitiatorContextReturnFlags Flags { get; }

    /// <summary>Whether more data is needed from the acceptor to complete the context.</summary>
    public bool MoreNeeded { get; }

    public SspiSecContext(SafeSspiContextHandle context, InitiatorContextReturnFlags flags, bool moreNeeded)
    {
        Context = context;
        Flags = flags;
        MoreNeeded = moreNeeded;
    }
}
