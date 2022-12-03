using System;
using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("ChiBi39.Aes128ChCh4")]

namespace ChiBi39.ChaCha20
{
    using Word = UInt32;
    
    public unsafe class ChaCha20Cipher
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void QuarterRound(Word* state, int x, int y, int z, int w)
        {
            Word a = state[x];
            Word b = state[y];
            Word c = state[z];
            Word d = state[w];
            a += b;
            d ^= a;
            d = (d << 16) | (d >> 16);
            c += d;
            b ^= c;
            b = (b << 12) | (b >> 20);
            a += b;
            d ^= a;
            d = (d << 8) | (d >> 24);
            c += d;
            b ^= c;
            b = (b << 7) | (b >> 25);
            state[x] = a;
            state[y] = b;
            state[z] = c;
            state[w] = d;
        }

        private const int DEFAULT_ROUND = 10;
        private const int WORD_SIZE_BYTE = sizeof(uint);
        private const int BLOCK_SIZE_WORD = 16;
        public const int BLOCK_SIZE_BYTE = BLOCK_SIZE_WORD * WORD_SIZE_BYTE;
        public const int KEY_SIZE_BYTE = 8 * WORD_SIZE_BYTE;
        public const int NONCE_SIZE_BYTE = 3 * WORD_SIZE_BYTE;
        internal readonly byte[] m_key;
        internal readonly byte[] m_nonce;
        private readonly Word[] m_initialState = new Word[BLOCK_SIZE_WORD];

        public ChaCha20Cipher(byte[] key, byte[] nonce)
        {
            m_key = key;
            m_nonce = nonce;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SetState(Word* state, Word counter)
        {
            fixed (byte* pKey = m_key, pNonce = m_nonce)
            {
                Word* pU32Key = (Word*) pKey;
                Word* pU32Nonce = (Word*) pNonce;
                state[0] = 0x61707865;
                state[1] = 0x3320646e;
                state[2] = 0x79622d32;
                state[3] = 0x6b206574;
                state[4] = pU32Key[0];
                state[5] = pU32Key[1];
                state[6] = pU32Key[2];
                state[7] = pU32Key[3];
                state[8] = pU32Key[4];
                state[9] = pU32Key[5];
                state[10] = pU32Key[6];
                state[11] = pU32Key[7];
                state[12] = counter;
                state[13] = pU32Nonce[0];
                state[14] = pU32Nonce[1];
                state[15] = pU32Nonce[2];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void ProcessBlock(byte* state, Word counter, int round = DEFAULT_ROUND)
        {
            fixed (Word* pInitialState = m_initialState)
            {
                Word* pU32State = (Word*) state;
                SetState(pU32State, counter);
                for (int i = 0; i < BLOCK_SIZE_WORD; ++i)
                {
                    pInitialState[i] = pU32State[i];
                }

                // クォーターラウンド4回で1ラウンドとし、2ラウンドセットで攪拌する。
                // これを10回繰り返して最大で20ラウンド繰り返す
                for (int i = 0; i < round; i++)
                {
                    // 1ラウンド目
                    QuarterRound(pU32State, 0, 4, 8, 12);
                    QuarterRound(pU32State, 1, 5, 9, 13);
                    QuarterRound(pU32State, 2, 6, 10, 14);
                    QuarterRound(pU32State, 3, 7, 11, 15);

                    // 2ラウンド目
                    QuarterRound(pU32State, 0, 5, 10, 15);
                    QuarterRound(pU32State, 1, 6, 11, 12);
                    QuarterRound(pU32State, 2, 7, 8, 13);
                    QuarterRound(pU32State, 3, 4, 9, 14);
                }

                // 最後に攪拌する前の状態を加算する
                for (int i = 0; i < BLOCK_SIZE_WORD; ++i)
                {
                    pU32State[i] += pInitialState[i];
                }
            }
        }
    }    
}

