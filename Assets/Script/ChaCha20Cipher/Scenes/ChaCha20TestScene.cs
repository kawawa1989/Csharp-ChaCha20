using System.IO;
using ChiBi39;
using Org.BouncyCastle.Crypto.Engines;
using UnityEngine;

public class ChaCha20TestScene : MonoBehaviour
{
    private byte[] m_cc20Buffer;
    private byte[] m_aes128Buffer;
    private byte[] m_aes128BufferOut;
    private ChaCha20Cipher m_cc20Cipher;
    private AesFastEngine m_aes;
    private byte[] m_aesNonce;

    // Start is called before the first frame update
    void Start()
    {
        var rnd = new System.Random(1000);
        // ChaCha20
        {
            byte[] key = new byte[ChaCha20Cipher.KEY_SIZE_BYTE];
            byte[] nonce = new byte[ChaCha20Cipher.NONCE_SIZE_BYTE];
            m_cc20Buffer = new byte[ChaCha20Cipher.BLOCK_SIZE_BYTE];
            rnd.NextBytes(key);
            rnd.NextBytes(nonce);
            m_cc20Cipher = new ChaCha20Cipher(key, nonce);
        }

        // AES128
        {
            m_aes128Buffer = new byte[16];
            m_aes128BufferOut = new byte[16];
            m_aesNonce = new byte[8];
            byte[] key = new byte[16];
            rnd.NextBytes(key);
            rnd.NextBytes(m_aesNonce);
            m_aes = new AesFastEngine();
            m_aes.Init(true, key);
        }
    }

    private unsafe void EncryptAes128Ctr(byte[] inputBytes)
    {
        float start = Time.realtimeSinceStartup;
        fixed (byte* pBuffer = m_aes128Buffer, pNonce = m_aesNonce, pBufferOut = m_aes128BufferOut, pInput = inputBytes)
        {
            uint blockCount = (uint) (inputBytes.Length / 16);
            uint* pU32Input = (uint*) pInput;
            ulong* pU64Buffer = (ulong*) pBuffer;
            pU64Buffer[0] = *(ulong*) pNonce;

            uint* pU32BufferOut = (uint*) pBufferOut;
            for (ulong counter = 0; counter < blockCount; ++counter)
            {
                pU64Buffer[1] = counter;
                m_aes.ProcessBlock(m_aes128Buffer, 0, m_aes128BufferOut, 0);
                pU32Input[0] ^= pU32BufferOut[0];
                pU32Input[1] ^= pU32BufferOut[1];
                pU32Input[2] ^= pU32BufferOut[2];
                pU32Input[3] ^= pU32BufferOut[3];
                pU32Input += 4;
            }
        }

        float end = Time.realtimeSinceStartup;
        Debug.Log($"EncryptAes128Ctr time: {end - start}");
    }

    private unsafe void EncryptChaCha20(byte[] inputBytes)
    {
        float start = Time.realtimeSinceStartup;
        fixed (byte* pBuffer = m_cc20Buffer, pInput = inputBytes)
        {
            uint blockCount = (uint) (inputBytes.Length / ChaCha20Cipher.BLOCK_SIZE_BYTE);
            uint* pU32Input = (uint*) pInput;
            uint* pU32Buffer = (uint*) pBuffer;
            for (uint counter = 0; counter < blockCount; ++counter)
            {
                m_cc20Cipher.ProcessBlock(pBuffer, counter, 8);
                pU32Input[0] ^= pU32Buffer[0];
                pU32Input[1] ^= pU32Buffer[1];
                pU32Input[2] ^= pU32Buffer[2];
                pU32Input[3] ^= pU32Buffer[3];
                pU32Input[4] ^= pU32Buffer[4];
                pU32Input[5] ^= pU32Buffer[5];
                pU32Input[6] ^= pU32Buffer[6];
                pU32Input[7] ^= pU32Buffer[7];
                pU32Input[8] ^= pU32Buffer[8];
                pU32Input[9] ^= pU32Buffer[9];
                pU32Input[10] ^= pU32Buffer[10];
                pU32Input[11] ^= pU32Buffer[11];
                pU32Input[12] ^= pU32Buffer[12];
                pU32Input[13] ^= pU32Buffer[13];
                pU32Input[14] ^= pU32Buffer[14];
                pU32Input[15] ^= pU32Buffer[15];
                pU32Input += 16;
            }
        }
        
        float end = Time.realtimeSinceStartup;
        Debug.Log($"EncryptChaCha20 time: {end - start}");
    }

    // Update is called once per frame
    void Update()
    {
        if (Input.GetKeyUp(KeyCode.A))
        {
            var bytes = File.ReadAllBytes("0002.bundle");
            EncryptChaCha20(bytes);
            File.WriteAllBytes("Encrypted.enc", bytes);
        }

        if (Input.GetKeyUp(KeyCode.S))
        {
            var bytes = File.ReadAllBytes("Encrypted.enc");
            EncryptChaCha20(bytes);
            File.WriteAllBytes("Decrypted.jpeg", bytes);
        }

        if (Input.GetKeyUp(KeyCode.D))
        {
            var bytes = File.ReadAllBytes("0002.bundle");
            EncryptAes128Ctr(bytes);
            File.WriteAllBytes("Encrypted_AES.enc", bytes);
        }

        if (Input.GetKeyUp(KeyCode.F))
        {
            var bytes = File.ReadAllBytes("Encrypted_AES.enc");
            EncryptAes128Ctr(bytes);
            File.WriteAllBytes("Decrypted_AES.jpeg", bytes);
        }
    }
}
