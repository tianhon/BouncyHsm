using BouncyHsm.Core.Services.Contracts;
using BouncyHsm.Core.Services.Contracts.Entities;
using BouncyHsm.Core.Services.Contracts.P11;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace BouncyHsm.Core.Services.P11Handlers.Common;

internal class CloudHsmAesGcmDecryptBufferedCipher : IBufferedCipher
{
    private readonly IBufferedCipher inner;
    private readonly KeyObject keyObject;
    private readonly int tagBits;
    private readonly byte[]? associatedText;

    private readonly byte[] ivBuffer = new byte[12];
    private int ivBufferPos = 0;
    private bool initialized = false;

    public CloudHsmAesGcmDecryptBufferedCipher(IBufferedCipher inner, KeyObject keyObject, int tagBits, byte[]? associatedText)
    {
        this.inner = inner;
        this.keyObject = keyObject;
        this.tagBits = tagBits;
        this.associatedText = associatedText;
    }

    public string AlgorithmName => this.inner.AlgorithmName;

    private void EnsureInitialized(byte[]? input, ref int inOff, ref int length)
    {
        if (this.initialized) return;

        while (this.ivBufferPos < 12 && length > 0)
        {
            this.ivBuffer[this.ivBufferPos++] = input![inOff++];
            length--;
        }

        if (this.ivBufferPos == 12)
        {
            if (this.keyObject is AesKeyObject aesKey)
            {
                this.inner.Init(false, new AeadParameters(new KeyParameter(aesKey.GetSecret()), this.tagBits, this.ivBuffer, this.associatedText));
                this.initialized = true;
            }
            else
            {
                throw new RpcPkcs11Exception(CKR.CKR_KEY_HANDLE_INVALID, "Mechanism CKM_CLOUDHSM_AES_GCM required AES key.");
            }
        }
    }

    private void EnsureInitialized(ReadOnlySpan<byte> input, out int consumed)
    {
        consumed = 0;
        if (this.initialized) return;

        while (this.ivBufferPos < 12 && consumed < input.Length)
        {
            this.ivBuffer[this.ivBufferPos++] = input[consumed++];
        }

        if (this.ivBufferPos == 12)
        {
            if (this.keyObject is AesKeyObject aesKey)
            {
                this.inner.Init(false, new AeadParameters(new KeyParameter(aesKey.GetSecret()), this.tagBits, this.ivBuffer, this.associatedText));
                this.initialized = true;
            }
            else
            {
                throw new RpcPkcs11Exception(CKR.CKR_KEY_HANDLE_INVALID, "Mechanism CKM_CLOUDHSM_AES_GCM required AES key.");
            }
        }
    }

    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        // Ignore parameters, we will init later when IV is available
        this.ivBufferPos = 0;
        this.initialized = false;
    }

    public int GetUpdateOutputSize(int inputLen)
    {
        return this.initialized ? this.inner.GetUpdateOutputSize(inputLen) : 0;
    }

    public int GetOutputSize(int inputLen)
    {
        int effectiveLen = this.initialized ? inputLen : Math.Max(0, inputLen - (12 - this.ivBufferPos));
        return this.inner.GetOutputSize(effectiveLen);
    }

    public byte[] ProcessByte(byte input)
    {
        if (!this.initialized)
        {
            this.ivBuffer[this.ivBufferPos++] = input;
            if (this.ivBufferPos == 12)
            {
                int dummyOffset = 0;
                int dummyLen = 0;
                this.EnsureInitialized(null, ref dummyOffset, ref dummyLen);
            }
            return Array.Empty<byte>();
        }

        return this.inner.ProcessByte(input);
    }

    public int ProcessByte(byte input, byte[] output, int outOff)
    {
        if (!this.initialized)
        {
            this.ivBuffer[this.ivBufferPos++] = input;
            if (this.ivBufferPos == 12)
            {
                int dummyOffset = 0;
                int dummyLen = 0;
                this.EnsureInitialized(null, ref dummyOffset, ref dummyLen);
            }
            return 0;
        }

        return this.inner.ProcessByte(input, output, outOff);
    }

    public int ProcessByte(byte input, Span<byte> output)
    {
        if (!this.initialized)
        {
            this.ivBuffer[this.ivBufferPos++] = input;
            if (this.ivBufferPos == 12)
            {
                int consumed = 0;
                this.EnsureInitialized(ReadOnlySpan<byte>.Empty, out consumed);
            }
            return 0;
        }

        return this.inner.ProcessByte(input, output);
    }

    public byte[] ProcessBytes(byte[] input)
    {
        int inOff = 0;
        int length = input.Length;
        this.EnsureInitialized(input, ref inOff, ref length);
        if (this.initialized && length > 0)
        {
            return this.inner.ProcessBytes(input, inOff, length);
        }
        return Array.Empty<byte>();
    }

    public byte[] ProcessBytes(byte[] input, int inOff, int length)
    {
        this.EnsureInitialized(input, ref inOff, ref length);
        if (this.initialized && length > 0)
        {
            return this.inner.ProcessBytes(input, inOff, length);
        }
        return Array.Empty<byte>();
    }

    public int ProcessBytes(byte[] input, byte[] output, int outOff)
    {
        return this.ProcessBytes(input, 0, input.Length, output, outOff);
    }

    public int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
    {
        this.EnsureInitialized(input, ref inOff, ref length);
        if (this.initialized && length > 0)
        {
            return this.inner.ProcessBytes(input, inOff, length, output, outOff);
        }
        return 0;
    }

    public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
    {
        this.EnsureInitialized(input, out int consumed);
        if (this.initialized && consumed < input.Length)
        {
            return this.inner.ProcessBytes(input.Slice(consumed), output);
        }
        return 0;
    }

    public byte[] DoFinal()
    {
        if (!this.initialized) throw new RpcPkcs11Exception(CKR.CKR_DATA_INVALID, "Ciphertext too short (no IV)");
        return this.inner.DoFinal();
    }

    public byte[] DoFinal(byte[] input)
    {
        int inOff = 0;
        int length = input.Length;
        this.EnsureInitialized(input, ref inOff, ref length);
        if (!this.initialized) throw new RpcPkcs11Exception(CKR.CKR_DATA_INVALID, "Ciphertext too short (no IV)");
        return this.inner.DoFinal(input, inOff, length);
    }

    public byte[] DoFinal(byte[] input, int inOff, int length)
    {
        this.EnsureInitialized(input, ref inOff, ref length);
        if (!this.initialized) throw new RpcPkcs11Exception(CKR.CKR_DATA_INVALID, "Ciphertext too short (no IV)");
        return this.inner.DoFinal(input, inOff, length);
    }

    public int DoFinal(byte[] output, int outOff)
    {
        if (!this.initialized) throw new RpcPkcs11Exception(CKR.CKR_DATA_INVALID, "Ciphertext too short (no IV)");
        return this.inner.DoFinal(output, outOff);
    }

    public int DoFinal(byte[] input, byte[] output, int outOff)
    {
        return this.DoFinal(input, 0, input.Length, output, outOff);
    }

    public int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff)
    {
        this.EnsureInitialized(input, ref inOff, ref length);
        if (!this.initialized) throw new RpcPkcs11Exception(CKR.CKR_DATA_INVALID, "Ciphertext too short (no IV)");
        return this.inner.DoFinal(input, inOff, length, output, outOff);
    }

    public int DoFinal(ReadOnlySpan<byte> input, Span<byte> output)
    {
        this.EnsureInitialized(input, out int consumed);
        if (!this.initialized) throw new RpcPkcs11Exception(CKR.CKR_DATA_INVALID, "Ciphertext too short (no IV)");
        return this.inner.DoFinal(input.Slice(consumed), output);
    }

    public int DoFinal(Span<byte> output)
    {
        if (!this.initialized) throw new RpcPkcs11Exception(CKR.CKR_DATA_INVALID, "Ciphertext too short (no IV)");
        return this.inner.DoFinal(output);
    }

    public void Reset()
    {
        this.inner.Reset();
        this.ivBufferPos = 0;
        this.initialized = false;
    }

    public int GetBlockSize()
    {
        return this.inner.GetBlockSize();
    }
}
