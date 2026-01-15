using BouncyHsm.Core.Services.Contracts;
using BouncyHsm.Core.Services.Contracts.Entities;
using BouncyHsm.Core.Services.Contracts.P11;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;

namespace BouncyHsm.Core.Services.P11Handlers.Common;

internal class CloudHsmAesGcmWrapper : IWrapper
{
    private readonly IBufferedCipher innerCipher;
    private readonly KeyObject wrappingKey;
    private readonly int tagBits;
    private readonly byte[]? nonce;
    private readonly byte[]? associatedText;
    private readonly CKM mechanismType;
    private readonly SecureRandom randomSource;
    private bool forWrapping;

    public CloudHsmAesGcmWrapper(KeyObject wrappingKey,
        int tagBits,
        byte[]? nonce,
        byte[]? associatedText,
        CKM mechanismType,
        SecureRandom randomSource)
    {
        this.innerCipher = CipherUtilities.GetCipher("AES/GCM/NOPADDING");
        this.wrappingKey = wrappingKey;
        this.tagBits = tagBits;
        this.nonce = nonce;
        this.associatedText = associatedText;
        this.mechanismType = mechanismType;
        this.randomSource = randomSource;
    }

    public string AlgorithmName => "AES/GCM/CloudHSM";

    public void Init(bool forWrapping, ICipherParameters parameters)
    {
        this.forWrapping = forWrapping;
    }

    public byte[] Wrap(byte[] input, int inOff, int length)
    {
        if (!this.forWrapping) throw new InvalidOperationException("Not initialized for wrapping.");

        byte[] iv = this.nonce ?? new byte[12];
        if (this.nonce == null)
        {
            this.randomSource.NextBytes(iv);
        }
        if (this.wrappingKey is AesKeyObject aesKey)
        {
            this.innerCipher.Init(true, new AeadParameters(new KeyParameter(aesKey.GetSecret()), this.tagBits, iv, this.associatedText));

            byte[] ciphertext = this.innerCipher.DoFinal(input, inOff, length);
            byte[] result = new byte[iv.Length + ciphertext.Length];
            Array.Copy(iv, 0, result, 0, iv.Length);
            Array.Copy(ciphertext, 0, result, iv.Length, ciphertext.Length);
            return result;
        }

        throw new RpcPkcs11Exception(CKR.CKR_KEY_HANDLE_INVALID, $"Mechanism {this.mechanismType} required AES key for wrapping.");
    }

    public byte[] Unwrap(byte[] input, int inOff, int length)
    {
        if (this.forWrapping) throw new InvalidOperationException("Not initialized for unwrapping.");

        if (length < 12)
        {
            throw new RpcPkcs11Exception(CKR.CKR_ENCRYPTED_DATA_LEN_RANGE, "Wrapped key too short for CKM_CLOUDHSM_AES_GCM (missing IV).");
        }

        byte[] iv = new byte[12];
        Array.Copy(input, inOff, iv, 0, 12);

        if (this.wrappingKey is AesKeyObject aesKey)
        {
            this.innerCipher.Init(false, new AeadParameters(new KeyParameter(aesKey.GetSecret()), this.tagBits, iv, this.associatedText));
            return this.innerCipher.DoFinal(input, inOff + 12, length - 12);
        }

        throw new RpcPkcs11Exception(CKR.CKR_KEY_HANDLE_INVALID, $"Mechanism {this.mechanismType} required AES key for unwrapping.");
    }
}
