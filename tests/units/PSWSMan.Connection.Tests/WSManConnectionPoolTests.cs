using System;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan.Connection.Tests;

/// <summary>Covers the lease bookkeeping. Connections are created lazily so nothing here opens a socket.</summary>
public class WSManConnectionPoolTests
{
    private static WSManConnectionPool NewPool(int maxConnections = int.MaxValue)
    {
        return new(new WSManConnectionOptions(new Uri("http://localhost:5985/wsman"), new FakeNegoCredential(rounds: 1))
        {
            MaxConnections = maxConnections,
        });
    }

    [Test]
    public async Task Rent_ReturnsIdleConnectionToNextCaller()
    {
        using WSManConnectionPool pool = NewPool();

        WSManHttpConnection first;
        using (WSManConnectionLease lease = pool.Rent())
        {
            first = lease.Connection;
        }

        using (WSManConnectionLease lease = pool.Rent())
        {
            await Assert.That(lease.Connection).IsSameReferenceAs(first);
        }

        await Assert.That(pool.OpenConnections).IsEqualTo(1);
    }

    [Test]
    public async Task Rent_ConcurrentLeasesGetDistinctConnections()
    {
        using WSManConnectionPool pool = NewPool();

        using WSManConnectionLease a = pool.Rent();
        using WSManConnectionLease b = pool.Rent();

        await Assert.That(a.Connection).IsNotSameReferenceAs(b.Connection);
        await Assert.That(pool.OpenConnections).IsEqualTo(2);
    }

    [Test]
    public async Task Rent_AtLimit_WaitsAndHonoursCancellation()
    {
        using WSManConnectionPool pool = NewPool(maxConnections: 1);

        WSManConnectionLease held = pool.Rent();
        WSManHttpConnection heldConnection = held.Connection;
        using CancellationTokenSource cts = new(TimeSpan.FromMilliseconds(200));

        Assert.Throws<OperationCanceledException>(() => pool.Rent(cts.Token));

        held.Dispose();
        using WSManConnectionLease next = pool.Rent();
        await Assert.That(next.Connection).IsSameReferenceAs(heldConnection);
        await Assert.That(pool.OpenConnections).IsEqualTo(1);
    }

    [Test]
    public async Task Rent_AtLimit_ReleasedByReturn()
    {
        using WSManConnectionPool pool = NewPool(maxConnections: 1);
        WSManConnectionLease held = pool.Rent();

        Task<WSManConnectionLease> waiting = Task.Run(() => pool.Rent());
        await Task.Delay(100);
        await Assert.That(waiting.IsCompleted).IsFalse();

        held.Dispose();
        using WSManConnectionLease next = await waiting.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(next.Connection).IsNotNull();
    }

    [Test]
    public async Task Return_DisposedConnectionIsDropped()
    {
        using WSManConnectionPool pool = NewPool();

        WSManHttpConnection dropped;
        using (WSManConnectionLease lease = pool.Rent())
        {
            dropped = lease.Connection;
            // Disposing marks the connection broken, the same state a failed request leaves it in.
            dropped.Dispose();
            await Assert.That(dropped.IsBroken).IsTrue();
        }

        await Assert.That(pool.OpenConnections).IsEqualTo(0);
        using WSManConnectionLease next = pool.Rent();
        await Assert.That(next.Connection).IsNotSameReferenceAs(dropped);
    }

    [Test]
    public async Task Lease_DoubleDisposeReturnsOnce()
    {
        using WSManConnectionPool pool = NewPool(maxConnections: 1);

        WSManConnectionLease lease = pool.Rent();
        lease.Dispose();
        lease.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = lease.Connection);
        using WSManConnectionLease next = pool.Rent();
        await Assert.That(next.Connection).IsNotNull();
    }

    [Test]
    public async Task Dispose_DisposesEveryConnectionAndRefusesRent()
    {
        WSManConnectionPool pool = NewPool();
        WSManConnectionLease rented = pool.Rent();
        WSManHttpConnection rentedConnection = rented.Connection;
        using (pool.Rent())
        { }

        pool.Dispose();
        rented.Dispose();

        await Assert.That(rentedConnection.IsBroken).IsTrue();
        await Assert.That(pool.OpenConnections).IsEqualTo(0);
        Assert.Throws<ObjectDisposedException>(() => pool.Rent());
    }
}
