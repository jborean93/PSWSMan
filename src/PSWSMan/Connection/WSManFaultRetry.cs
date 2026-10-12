using System;
using System.Collections.Generic;
using System.Threading;
using PSWSMan.Lib;

namespace PSWSMan.Connection;

/// <summary>A set of server faults that are retried by sending a new request with a new message id.</summary>
/// <remarks>
/// Only use this for faults where the server has finished with the original request and left nothing behind that a
/// new one would duplicate. A transport failure where the server may still hold the request is a different problem,
/// see <see cref="WinRSReceivePump"/>.
/// </remarks>
internal sealed class WSManFaultRetry
{
    /// <summary>The retry count that retries the faults for as long as the server returns them.</summary>
    public const int Always = -1;

    private readonly HashSet<int> _faultCodes;

    /// <summary>A short description of the faults used in trace messages.</summary>
    public string Name { get; }

    /// <summary>How many times to retry, or <see cref="Always"/>.</summary>
    public int Retries { get; }

    /// <summary>How long to wait before each retry.</summary>
    public TimeSpan Delay { get; }

    // TEMP: CI diagnostics for the Create retry, remove before merging.
    public bool WriteToConsole { get; init; }

    /// <summary>Creates a retry rule.</summary>
    /// <param name="name">A short description of the faults used in trace messages.</param>
    /// <param name="retries">How many times to retry, or <see cref="Always"/>.</param>
    /// <param name="delay">How long to wait before each retry.</param>
    /// <param name="faultCodes">The <see cref="WSManFault.WSManFaultCode"/> values to retry.</param>
    public WSManFaultRetry(string name, int retries, TimeSpan delay, params int[] faultCodes)
    {
        if (retries < Always)
        {
            throw new ArgumentOutOfRangeException(nameof(retries), "The retry count must be -1 or more.");
        }
        if (delay < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(delay), "The retry delay cannot be negative.");
        }

        Name = name;
        Retries = retries;
        Delay = delay;
        _faultCodes = new(faultCodes);
    }

    /// <summary>Whether the fault is one of the codes this rule retries.</summary>
    public bool Matches(WSManFault fault) => fault.WSManFaultCode is int code && _faultCodes.Contains(code);

    /// <summary>Whether another retry is allowed after <paramref name="retried"/> retries.</summary>
    public bool CanRetry(int retried) => Retries == Always || retried < Retries;

    /// <summary>Sends a request, building a new one and sending it again when the server faults with a retried code.</summary>
    /// <typeparam name="T">The response type.</typeparam>
    /// <param name="operation">The operation name used in trace messages.</param>
    /// <param name="rules">The faults to retry, the first rule that matches a fault is used.</param>
    /// <param name="createRequest">Builds the request, called once per attempt so each has a new message id.</param>
    /// <param name="send">Sends the request and parses the response.</param>
    /// <param name="trace">Optional callback for trace messages.</param>
    /// <param name="cancellationToken">
    /// Stops the retries, a retried fault or a wait for the next attempt throws when cancelled.
    /// </param>
    /// <returns>The response.</returns>
    public static T Invoke<T>(
        string operation,
        IReadOnlyList<WSManFaultRetry> rules,
        Func<WSManRequest> createRequest,
        Func<WSManRequest, T> send,
        Action<string, Exception?>? trace,
        CancellationToken cancellationToken)
    {
        int[] retried = new int[rules.Count];
        WSManFaultRetry? lastRule = null;
        while (true)
        {
            WSManRequest request = createRequest();
            try
            {
                T response = send(request);
                // TEMP: CI diagnostics for the Create retry, remove before merging.
                if (lastRule?.WriteToConsole == true)
                {
                    Console.WriteLine($"PSWSMan TEMP: {operation} succeeded after retrying {lastRule.Name}");
                }
                return response;
            }
            catch (WSManFault e) when (TryGetRule(rules, retried, e, out int index))
            {
                // The fault would be retried, report it as cancelled like a cancelled request rather than as a fault.
                cancellationToken.ThrowIfCancellationRequested();

                WSManFaultRetry rule = rules[index];
                lastRule = rule;
                int attempt = ++retried[index];
                string limit = rule.Retries == Always ? "" : $"/{rule.Retries}";
                trace?.Invoke($"{operation} failed with {rule.Name}, retry {attempt}{limit} in {rule.Delay}", e);
                // TEMP: CI diagnostics for the Create retry, remove before merging.
                if (rule.WriteToConsole)
                {
                    Console.WriteLine(
                        $"PSWSMan TEMP: {operation} failed with {rule.Name}, retry {attempt}{limit}\n{e.Message}");
                }

                if (rule.Delay > TimeSpan.Zero && cancellationToken.WaitHandle.WaitOne(rule.Delay))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }
            }
            // TEMP: CI diagnostics for the Create retry, remove before merging.
            catch (WSManFault e) when (lastRule?.WriteToConsole == true)
            {
                Console.WriteLine($"PSWSMan TEMP: {operation} failed after retrying {lastRule.Name} with " +
                    $"0x{e.WSManFaultCode ?? 0:X8}\n{e.Message}");
                throw;
            }
        }
    }

    private static bool TryGetRule(IReadOnlyList<WSManFaultRetry> rules, int[] retried, WSManFault fault,
        out int index)
    {
        for (int i = 0; i < rules.Count; i++)
        {
            if (rules[i].Matches(fault))
            {
                index = i;
                return rules[i].CanRetry(retried[i]);
            }
        }

        index = -1;
        return false;
    }
}
