using PSWSMan.Lib;
using System;
using System.Collections.Generic;
using System.Threading;

namespace PSWSMan.Connection;

/// <summary>A pool of authenticated connections to one WSMan endpoint.</summary>
/// <remarks>
/// A rented connection is owned exclusively by the holder of the lease until it is returned. Control operations rent
/// a connection for a single request while a receive pump rents one for its lifetime, which is how a long running
/// Receive never blocks a Send or Signal to the same shell. Broken connections are disposed on return instead of
/// being reused.
/// </remarks>
internal sealed class WSManConnectionPool : IDisposable
{
    private readonly object _lock = new();
    private readonly Stack<WSManHttpConnection> _idle = new();
    private readonly HashSet<WSManHttpConnection> _all = new();
    private readonly SemaphoreSlim _slots;
    private bool _disposed;

    /// <summary>The options every connection in the pool is created with.</summary>
    public WSManConnectionOptions Options { get; }

    /// <summary>The number of connections currently open, rented or idle.</summary>
    public int OpenConnections
    {
        get
        {
            lock (_lock)
            {
                return _all.Count;
            }
        }
    }

    /// <summary>Creates a pool for the endpoint described by the options.</summary>
    /// <param name="options">The options for the endpoint.</param>
    public WSManConnectionPool(WSManConnectionOptions options)
    {
        options.Validate();
        Options = options;
        _slots = new SemaphoreSlim(options.MaxConnections, options.MaxConnections);
    }

    /// <summary>Rents a connection for exclusive use until the lease is disposed.</summary>
    /// <param name="cancellationToken">Cancels the wait for a free slot when the pool is at its limit.</param>
    /// <returns>The lease holding the connection.</returns>
    public WSManConnectionLease Rent(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _slots.Wait(cancellationToken);

        try
        {
            WSManHttpConnection connection;
            lock (_lock)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (!_idle.TryPop(out connection!))
                {
                    connection = new WSManHttpConnection(Options);
                    _all.Add(connection);
                }
            }

            return new WSManConnectionLease(this, connection);
        }
        catch
        {
            _slots.Release();
            throw;
        }
    }

    /// <summary>Sends a request on a rented connection and parses the response.</summary>
    /// <typeparam name="T">The expected response payload type.</typeparam>
    /// <param name="request">The request to send.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The parsed response.</returns>
    /// <exception cref="WSManFault">The server returned a fault.</exception>
    public T Invoke<T>(WSManRequest request, CancellationToken cancellationToken = default)
        where T : IWSManPayload<T>
    {
        using WSManConnectionLease lease = Rent(cancellationToken);
        ReadOnlyMemory<byte> response = lease.Connection.Send(request.Content, cancellationToken);
        return T.Parse(response.Span, request.MessageId);
    }

    internal void Return(WSManHttpConnection connection)
    {
        bool dispose;
        lock (_lock)
        {
            dispose = _disposed || connection.IsBroken;
            if (dispose)
            {
                _all.Remove(connection);
            }
            else
            {
                _idle.Push(connection);
            }
        }

        if (dispose)
        {
            connection.Dispose();
        }
        _slots.Release();
    }

    /// <summary>Disposes every connection, including rented ones which aborts any request in flight on them.</summary>
    public void Dispose()
    {
        WSManHttpConnection[] connections;
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;

            connections = new WSManHttpConnection[_all.Count];
            _all.CopyTo(connections);
            _all.Clear();
            _idle.Clear();
        }

        foreach (WSManHttpConnection connection in connections)
        {
            connection.Dispose();
        }
    }
}

/// <summary>Exclusive ownership of a pooled connection, returned to the pool on dispose.</summary>
internal sealed class WSManConnectionLease : IDisposable
{
    private readonly WSManConnectionPool _pool;
    private WSManHttpConnection? _connection;

    /// <summary>The rented connection.</summary>
    public WSManHttpConnection Connection => _connection
        ?? throw new ObjectDisposedException(nameof(WSManConnectionLease));

    internal WSManConnectionLease(WSManConnectionPool pool, WSManHttpConnection connection)
    {
        _pool = pool;
        _connection = connection;
    }

    /// <summary>Returns the connection to the pool.</summary>
    public void Dispose()
    {
        WSManHttpConnection? connection = Interlocked.Exchange(ref _connection, null);
        if (connection is not null)
        {
            _pool.Return(connection);
        }
    }
}
