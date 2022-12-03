using System;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using ChiBi39.ChaCha20;
using Org.BouncyCastle.Crypto.Engines;
using UnityEngine;
using Random = System.Random;

namespace ChiBi39.Aes128ChCh4
{
    public unsafe class Aes128ChCh4StreamCipher : StreamCipher.StreamCipher
    {
        // The S box
        private static readonly byte[] S =
        {
            99, 124, 119, 123, 242, 107, 111, 197,
            48, 1, 103, 43, 254, 215, 171, 118,
            202, 130, 201, 125, 250, 89, 71, 240,
            173, 212, 162, 175, 156, 164, 114, 192,
            183, 253, 147, 38, 54, 63, 247, 204,
            52, 165, 229, 241, 113, 216, 49, 21,
            4, 199, 35, 195, 24, 150, 5, 154,
            7, 18, 128, 226, 235, 39, 178, 117,
            9, 131, 44, 26, 27, 110, 90, 160,
            82, 59, 214, 179, 41, 227, 47, 132,
            83, 209, 0, 237, 32, 252, 177, 91,
            106, 203, 190, 57, 74, 76, 88, 207,
            208, 239, 170, 251, 67, 77, 51, 133,
            69, 249, 2, 127, 80, 60, 159, 168,
            81, 163, 64, 143, 146, 157, 56, 245,
            188, 182, 218, 33, 16, 255, 243, 210,
            205, 12, 19, 236, 95, 151, 68, 23,
            196, 167, 126, 61, 100, 93, 25, 115,
            96, 129, 79, 220, 34, 42, 144, 136,
            70, 238, 184, 20, 222, 94, 11, 219,
            224, 50, 58, 10, 73, 6, 36, 92,
            194, 211, 172, 98, 145, 149, 228, 121,
            231, 200, 55, 109, 141, 213, 78, 169,
            108, 86, 244, 234, 101, 122, 174, 8,
            186, 120, 37, 46, 28, 166, 180, 198,
            232, 221, 116, 31, 75, 189, 139, 138,
            112, 62, 181, 102, 72, 3, 246, 14,
            97, 53, 87, 185, 134, 193, 29, 158,
            225, 248, 152, 17, 105, 217, 142, 148,
            155, 30, 135, 233, 206, 85, 40, 223,
            140, 161, 137, 13, 191, 230, 66, 104,
            65, 153, 45, 15, 176, 84, 187, 22,
        };
        
        private static uint SubWord(uint x)
        {
            return (uint) S[x & 255]
                   | (((uint) S[(x >> 8) & 255]) << 8)
                   | (((uint) S[(x >> 16) & 255]) << 16)
                   | (((uint) S[(x >> 24) & 255]) << 24);
        }
        
        private static uint Shift(uint r, int shift)
        {
            return (r >> shift) | (r << (32 - shift));
        }
        
        private readonly struct Processor
        {
            private readonly byte* m_aesNonce;
            private readonly byte* m_aesTemp;
            private readonly uint* m_cc20Nonce;
            private readonly uint* m_cc20Key;

            public Processor(byte* aesNonce, byte* aesTemp, uint* cc20Nonce, uint* cc20Key)
            {
                m_aesNonce = aesNonce;
                m_aesTemp = aesTemp;
                m_cc20Nonce = cc20Nonce;
                m_cc20Key = cc20Key;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void UpdateAesVector(ulong counter)
            {
                ((ulong*) m_aesTemp)[0] = *((ulong*) m_aesNonce);
                ((ulong*) m_aesTemp)[1] = counter;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void UpdateAesVector(byte* keyStream, int keyStreamOffset, ulong counter)
            {
                ((ulong*) m_aesTemp)[0] = *((ulong*) m_aesNonce) ^ *((ulong*) &keyStream[keyStreamOffset]);
                ((ulong*) m_aesTemp)[1] = counter;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void UpdateChaChaNonceAndKey(uint* keyStream)
            {
                m_cc20Nonce[0] ^= keyStream[0];
                m_cc20Nonce[1] ^= keyStream[1];
                m_cc20Nonce[2] ^= keyStream[2];
                m_cc20Key[0] ^= keyStream[3];
                m_cc20Key[1] ^= keyStream[4];
                m_cc20Key[2] ^= keyStream[5];
                m_cc20Key[3] ^= keyStream[6];
                m_cc20Key[4] ^= keyStream[7];
                m_cc20Key[5] ^= keyStream[8];
                m_cc20Key[6] ^= keyStream[9];
                m_cc20Key[7] ^= keyStream[10];
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Xor(byte* bufferPointer, byte* keyStream, int index, int length)
            {
                byte* buffer = bufferPointer;
                byte* cipher = &keyStream[index];

                while (length >= sizeof(long))
                {
                    *(long*) buffer ^= *(long*) cipher;
                    buffer += sizeof(long);
                    cipher += sizeof(long);
                    length -= sizeof(long);
                }

                if (length >= sizeof(int))
                {
                    *(int*) buffer ^= *(int*) cipher;
                    buffer += sizeof(int);
                    cipher += sizeof(int);
                    length -= sizeof(int);
                }

                if (length >= sizeof(short))
                {
                    *(short*) buffer ^= *(short*) cipher;
                    buffer += sizeof(short);
                    cipher += sizeof(short);
                    length -= sizeof(short);
                }

                if (length >= sizeof(byte))
                {
                    *buffer ^= *cipher;
                }
            }
        }

        private const int AES_BLOCK_SIZE_BYTE = 16;
        private const int KEY_STREAM_LENGTH = 512;
        private readonly ChaCha20Cipher m_cc20Cipher;
        private readonly AesFastEngine m_aesCipher;
        private readonly byte[] m_keyStream = new byte[KEY_STREAM_LENGTH];
        private readonly byte[] m_temp = new byte[AES_BLOCK_SIZE_BYTE];
        private readonly byte[] m_aesNonce;

        public Aes128ChCh4StreamCipher(byte[] key, byte[] aesNonce)
        {
            m_aesNonce = aesNonce;
            m_aesCipher = new AesFastEngine();
            m_aesCipher.Init(true, key);
            using (SHA512 sha = SHA512.Create())
            {
                byte[] hash = sha.ComputeHash(key);
                byte[] cc20Key = hash.AsSpan(0, ChaCha20Cipher.KEY_SIZE_BYTE).ToArray();
                byte[] cc20Nonce = hash.AsSpan(ChaCha20Cipher.KEY_SIZE_BYTE, ChaCha20Cipher.NONCE_SIZE_BYTE).ToArray();
                m_cc20Cipher = new ChaCha20Cipher(cc20Key, cc20Nonce);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void GenerateKeyStream(ref Processor processor, byte* keyStream, ulong counter)
        {
            byte* keyStreamCurrentAddress = keyStream;
            // 最初の64バイトブロック
            // Counterモードによる暗号化を16バイトに対して行い、このブロック情報をもとに残りの48バイトブロックを生成する
            processor.UpdateAesVector(counter);
            m_aesCipher.ProcessBlock(m_temp, 0, m_keyStream, 0);
            uint t0 = ((uint*) keyStream)[0];
            uint t1 = ((uint*) keyStream)[1];
            uint t2 = ((uint*) keyStream)[2];
            uint t3 = ((uint*) keyStream)[3];
            const int expansionTime = (ChaCha20Cipher.BLOCK_SIZE_BYTE - AES_BLOCK_SIZE_BYTE) / AES_BLOCK_SIZE_BYTE;
            for (int i = 0; i < expansionTime; ++i)
            {
                int offset = (i + 1) * 4;
                uint u = SubWord(Shift(t3, 8));
                t0 ^= u;
                t1 ^= t0;
                t2 ^= t1;
                t3 ^= t2;
                ((uint*) keyStream)[offset] = t0;
                ((uint*) keyStream)[offset + 1] = t1;
                ((uint*) keyStream)[offset + 2] = t2;
                ((uint*) keyStream)[offset + 3] = t3;
            }

            // 生成したAES暗号文とChaChaで使用するNonce, Keyを混ぜる
            // 混ぜた値が次のChaCha暗号で実際に使用されるNonce, Keyとなる。
            processor.UpdateChaChaNonceAndKey((uint*) keyStreamCurrentAddress);
            keyStreamCurrentAddress += ChaCha20Cipher.BLOCK_SIZE_BYTE;

            // ここからChaCha20 による暗号
            // 2ラウンドのみ処理する
            const int remainBlockCount = (KEY_STREAM_LENGTH / ChaCha20Cipher.BLOCK_SIZE_BYTE) - 1;
            for (int i = 0; i < remainBlockCount; ++i)
            {
                m_cc20Cipher.ProcessBlock(keyStreamCurrentAddress, (uint) counter++, 1);
                // 生成した暗号文を使って次の暗号で使用する Key と Nonce を計算
                processor.UpdateChaChaNonceAndKey((uint*) keyStreamCurrentAddress);
                keyStreamCurrentAddress += ChaCha20Cipher.BLOCK_SIZE_BYTE;
            }
        }

        public override void ProcessStream(byte[] buffer, int offset, int count, long streamPosition)
        {
            fixed (byte* pFixedBuffer = &buffer[offset], pNonce = m_aesNonce, pTemp = m_temp, pKeyStream = m_keyStream)
            fixed (byte* pCc20Key = m_cc20Cipher.m_key, pCc20Nonce = m_cc20Cipher.m_nonce)
            {
                var processor = new Processor(pNonce, pTemp, (uint*) pCc20Nonce, (uint*) pCc20Key);
                byte* pBuffer = pFixedBuffer;
                uint blockCount = (uint) (streamPosition / KEY_STREAM_LENGTH + 1);
                int blockPosition = (int) (streamPosition % KEY_STREAM_LENGTH);
                // 最初の暗号ブロックの端数を先に処理する
                int firstBlockFraction = KEY_STREAM_LENGTH - blockPosition;
                if (firstBlockFraction > 0)
                {
                    GenerateKeyStream(ref processor, pKeyStream, blockCount++);
                    processor.Xor(pBuffer, pKeyStream, blockPosition, firstBlockFraction);
                    count -= firstBlockFraction;
                    pBuffer += firstBlockFraction;
                }

                int numberOfBlocks = count / KEY_STREAM_LENGTH;
                for (int i = 0; i < numberOfBlocks; ++i)
                {
                    GenerateKeyStream(ref processor, pKeyStream, blockCount++);
                    processor.Xor(pBuffer, pKeyStream, 0, KEY_STREAM_LENGTH);
                    pBuffer += KEY_STREAM_LENGTH;
                }

                int remaining = count % KEY_STREAM_LENGTH;
                if (remaining > 0)
                {
                    GenerateKeyStream(ref processor, pKeyStream, blockCount);
                    processor.Xor(pBuffer, pKeyStream, 0, remaining);
                }
            }
        }
    }
}

