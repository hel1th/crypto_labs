using System.Buffers.Binary;
using System.Collections.Concurrent;
using CryptoLab1.Core;

namespace CryptoLab1.Deal
{

    public class DesRoundFunctionAdapter : IRoundFunction
    {
        private readonly ISymmetricCipher _defaultDes;
        private readonly ConcurrentDictionary<ulong, ThreadLocal<ISymmetricCipher>> _cache = new();

        public DesRoundFunctionAdapter(ISymmetricCipher des)
        {
            _defaultDes = des;
        }

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            var ukey = BinaryPrimitives.ReadUInt64BigEndian(roundKey);
            var threadDes = _cache.GetOrAdd(ukey, k => new ThreadLocal<ISymmetricCipher>(() =>
            {
                var des = Des.DesCipherFactory.Create();
                var keyBytes = new byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(keyBytes, k);
                des.SetKey(keyBytes);
                return des;
            }));

            var cipher = threadDes.Value ?? _defaultDes;
            return cipher.Encrypt(inputBlock);
        }

        public void Transform(ReadOnlySpan<byte> inputBlock, ReadOnlySpan<byte> roundKey, Span<byte> destination)
        {
            var ukey = BinaryPrimitives.ReadUInt64BigEndian(roundKey);
            var threadDes = _cache.GetOrAdd(ukey, k => new ThreadLocal<ISymmetricCipher>(() =>
            {
                var des = Des.DesCipherFactory.Create();
                var keyBytes = new byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(keyBytes, k);
                des.SetKey(keyBytes);
                return des;
            }));

            var cipher = threadDes.Value ?? _defaultDes;
            cipher.Encrypt(inputBlock, destination);
        }
    }
}
