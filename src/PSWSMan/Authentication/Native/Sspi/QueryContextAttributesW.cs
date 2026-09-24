namespace PSWSMan.Authentication.Native;

using unsafe QueryContextAttributesWFn = delegate* unmanaged[Stdcall]<
    Helpers.SecHandle*, // phContext
    SecPkgAttribute,    // ulAttribute
    void*,              // pBuffer
    int>;

internal sealed unsafe partial class SspiProvider
{
    private readonly QueryContextAttributesWFn _queryContextAttributesW =
        (QueryContextAttributesWFn)GetExport(module, "QueryContextAttributesW");

    /// <summary>Query the security context for a specific value.</summary>
    /// <remarks>
    /// The buffer must be the struct type documented for the attribute. Attributes whose struct contains package
    /// allocated pointers need those released with <c>FreeContextBuffer</c> by the caller.
    /// </remarks>
    /// <param name="context">The security context to query.</param>
    /// <param name="attribute">The type of value to query.</param>
    /// <param name="buffer">Pointer to the struct that receives the queried value.</param>
    /// <exception cref="SspiException">Failure trying to query the requested value.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--general">QueryContextAttributes</see>
    public void QueryContextAttributes(
        SafeSspiContextHandle context,
        SecPkgAttribute attribute,
        void* buffer)
    {
        using SafeHandleRef contextRef = new(context);

        int res = _queryContextAttributesW(contextRef.As<Helpers.SecHandle>(), attribute, buffer);
        if (res != 0)
            throw new SspiException(res, "QueryContextAttributes");
    }
}
