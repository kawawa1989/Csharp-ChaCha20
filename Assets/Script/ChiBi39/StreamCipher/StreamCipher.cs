using System;

namespace ChiBi39.StreamCipher
{
    public abstract class StreamCipher : IDisposable
    {
        public abstract void ProcessStream(byte[] buffer, int offset, int count, long streamPosition);

        public virtual void Dispose()
        {
        }
    }
}
