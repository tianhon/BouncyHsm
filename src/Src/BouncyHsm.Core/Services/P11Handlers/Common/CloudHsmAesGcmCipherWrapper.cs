using BouncyHsm.Core.Services.Bc;
using BouncyHsm.Core.Services.Contracts;
using BouncyHsm.Core.Services.Contracts.Entities;
using BouncyHsm.Core.Services.Contracts.P11;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;

namespace BouncyHsm.Core.Services.P11Handlers.Common;

internal class CloudHsmAesGcmCipherWrapper : ICipherWrapper
{
    private readonly int tagBits;
    private readonly byte[]? nonce;
    private readonly byte[]? associatedText;
    private readonly CKM mechanismType;
    private readonly SecureRandom randomSource;
    private readonly ILoggerFactory loggerFactory;
    private readonly ILogger<CloudHsmAesGcmCipherWrapper> logger;

    public CloudHsmAesGcmCipherWrapper(int tagBits,
        byte[]? nonce,
        byte[]? associatedText,
        CKM mechanismType,
        SecureRandom randomSource,
        ILoggerFactory loggerFactory)
    {
        this.tagBits = tagBits;
        this.nonce = nonce;
        this.associatedText = associatedText;
        this.mechanismType = mechanismType;
        this.randomSource = randomSource;
        this.loggerFactory = loggerFactory;
        this.logger = loggerFactory.CreateLogger<CloudHsmAesGcmCipherWrapper>();
    }

    public CipherUinion IntoEncryption(KeyObject keyObject)
    {
        this.logger.LogTrace("Entering to IntoEncryption with object id {objectId}.", keyObject.Id);

        byte[] iv = this.nonce ?? new byte[12];
        if (this.nonce == null)
        {
            this.randomSource.NextBytes(iv);
        }
        IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NOPADDING");

        if (keyObject is AesKeyObject aesKey)
        {
            cipher.Init(true, new AeadParameters(new KeyParameter(aesKey.GetSecret()), this.tagBits, iv, this.associatedText));
            return new CipherUinion.BufferedCipher(new CloudHsmAesGcmBufferedCipher(cipher, iv));
        }

        throw new RpcPkcs11Exception(CKR.CKR_KEY_HANDLE_INVALID, $"Mechanism {this.mechanismType} required AES key.");
    }

    public CipherUinion IntoDecryption(KeyObject keyObject)
    {
        this.logger.LogTrace("Entering to IntoDecryption with object id {objectId}.", keyObject.Id);

        IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NOPADDING");
        // Initialization of 'cipher' will happen inside CloudHsmAesGcmDecryptBufferedCipher when IV is read.

        return new CipherUinion.BufferedCipher(new CloudHsmAesGcmDecryptBufferedCipher(cipher, keyObject, this.tagBits, this.associatedText));
    }

    public IWrapper IntoWrapping(KeyObject keyObject)
    {
        this.logger.LogTrace("Entering to IntoWrapping with object id {objectId}.", keyObject.Id);
        return new CloudHsmAesGcmWrapper(keyObject, this.tagBits, this.nonce, this.associatedText, this.mechanismType, this.randomSource);
    }

    public IWrapper IntoUnwrapping(KeyObject keyObject)
    {
        this.logger.LogTrace("Entering to IntoUnwrapping with object id {objectId}.", keyObject.Id);
        return new CloudHsmAesGcmWrapper(keyObject, this.tagBits, this.nonce, this.associatedText, this.mechanismType, this.randomSource);
    }
}
