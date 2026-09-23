using System;

namespace PSWSMan.Lib;

/// <summary>A WSMan request envelope to send to the server.</summary>
/// <param name="MessageId">The wsa:MessageID of the request, the response RelatesTo value should match this.</param>
/// <param name="Content">The WSMan envelope encoded as UTF-8 bytes.</param>
public sealed record WSManRequest(Guid MessageId, byte[] Content);
