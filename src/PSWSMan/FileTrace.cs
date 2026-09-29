using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;

namespace PSWSMan;

/// <summary>Writes the diagnostic messages of a connection to the file set by the TracePath option.</summary>
internal static class FileTrace
{
    // One lock per file so connections tracing to the same file do not interleave partial lines.
    private static readonly ConcurrentDictionary<string, object> s_locks = new(StringComparer.Ordinal);

    /// <summary>Creates a trace callback that appends each message to a file.</summary>
    /// <param name="path">The absolute path of the file, null or empty for no file trace.</param>
    /// <returns>The callback, or null when no path is set.</returns>
    public static Action<string>? Create(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        string fullPath = Path.GetFullPath(path);
        object fileLock = s_locks.GetOrAdd(fullPath, _ => new object());
        return message =>
        {
            try
            {
                // Every line gets the timestamp and thread, including the lines of a multi-line message like an
                // exception with its stack trace, so any line can be filtered and still be placed in time.
                string prefix =
                    $"{DateTimeOffset.Now:yyyy-MM-ddTHH:mm:ss.fffzzz} [{Environment.CurrentManagedThreadId}] ";
                StringBuilder text = new();
                foreach (string line in message.Split('\n'))
                {
                    text.Append(prefix).Append(line.TrimEnd('\r')).Append('\n');
                }

                lock (fileLock)
                {
                    File.AppendAllText(fullPath, text.ToString());
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Tracing is best effort, it must never fail the connection.
            }
        };
    }
}
