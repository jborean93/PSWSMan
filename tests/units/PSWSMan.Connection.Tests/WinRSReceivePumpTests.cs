using System;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading.Tasks;
using PSWSMan.Lib;

namespace PSWSMan.Connection.Tests;

/// <summary>Covers the retry decisions of the pump, the loop itself needs a real server.</summary>
public class WinRSReceivePumpTests
{
    [Test]
    [Arguments(1, 2)]
    [Arguments(2, 4)]
    [Arguments(3, 8)]
    [Arguments(5, 32)]
    public async Task GetRetryDelay_DoublesEachAttempt(int attempt, int expectedSeconds)
    {
        TimeSpan delay = WinRSReceivePump.GetRetryDelay(TimeSpan.FromSeconds(2), attempt);

        await Assert.That(delay).IsEqualTo(TimeSpan.FromSeconds(expectedSeconds));
    }

    [Test]
    public async Task GetRetryDelay_CapsGrowthForLargeAttempts()
    {
        TimeSpan sixth = WinRSReceivePump.GetRetryDelay(TimeSpan.FromSeconds(2), 6);
        TimeSpan hundredth = WinRSReceivePump.GetRetryDelay(TimeSpan.FromSeconds(2), 100);

        await Assert.That(sixth).IsEqualTo(TimeSpan.FromSeconds(64));
        await Assert.That(hundredth).IsEqualTo(sixth);
    }

    [Test]
    public async Task GetRetryDelay_ZeroBackoffIsZero()
    {
        await Assert.That(WinRSReceivePump.GetRetryDelay(TimeSpan.Zero, 3)).IsEqualTo(TimeSpan.Zero);
    }

    [Test]
    public void GetRetryDelay_RejectsAttemptBelowOne()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => WinRSReceivePump.GetRetryDelay(TimeSpan.FromSeconds(1), 0));
    }

    [Test]
    public async Task IsRetryableError_TransportFailuresAreRetried()
    {
        await Assert.That(WinRSReceivePump.IsRetryableError(new TimeoutException())).IsTrue();
        await Assert.That(WinRSReceivePump.IsRetryableError(new HttpRequestException())).IsTrue();
        await Assert.That(WinRSReceivePump.IsRetryableError(new IOException())).IsTrue();
        await Assert.That(WinRSReceivePump.IsRetryableError(new SocketException())).IsTrue();
    }

    [Test]
    public async Task IsRetryableError_ProtocolAndCancellationAreNot()
    {
        await Assert.That(WinRSReceivePump.IsRetryableError(new OperationCanceledException())).IsFalse();
        await Assert.That(WinRSReceivePump.IsRetryableError(new AuthenticationException())).IsFalse();
        await Assert.That(WinRSReceivePump.IsRetryableError(new WSManTransportException("bad"))).IsFalse();
        await Assert.That(WinRSReceivePump.IsRetryableError(new InvalidOperationException())).IsFalse();
    }
}
