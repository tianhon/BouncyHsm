using BouncyHsm.Core.Services.Contracts;
using BouncyHsm.Core.Services.Contracts.P11;
using BouncyHsm.Core.Services.P11Handlers.Common;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using BouncyHsm.Core.Services.Contracts.Entities;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;

namespace BouncyHsm.Core.Tests.Services.P11Handlers;

[TestClass]
public class CloudHsmAesGcmTests
{
    [TestMethod]
    public void Encrypt_PrependsIv()
    {
        byte[] iv = new byte[12];
        new SecureRandom().NextBytes(iv);
        
        Mock<IBufferedCipher> innerMock = new Mock<IBufferedCipher>();
        innerMock.Setup(m => m.DoFinal(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>())).Returns(new byte[] { 1, 2, 3 });
        
        CloudHsmAesGcmBufferedCipher cipher = new CloudHsmAesGcmBufferedCipher(innerMock.Object, iv);
        
        byte[] result = cipher.DoFinal(new byte[] { 4, 5, 6 }, 0, 3);
        
        Assert.AreEqual(12 + 3, result.Length);
        CollectionAssert.AreEqual(iv, result.Take(12).ToArray());
        CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, result.Skip(12).ToArray());
    }

    [TestMethod]
    public void Decrypt_ExtractsIv()
    {
        byte[] iv = new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] ciphertext = new byte[] { 2, 2, 2 };
        byte[] combined = new byte[15];
        iv.CopyTo(combined, 0);
        ciphertext.CopyTo(combined, 12);
        
        Mock<IBufferedCipher> innerMock = new Mock<IBufferedCipher>();
        innerMock.Setup(m => m.DoFinal(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>())).Returns(new byte[] { 3, 3, 3 });
        
        AesKeyObject aesKey = new AesKeyObject();
        aesKey.SetSecret(new byte[16]);
        aesKey.CkaDecrypt = true;
        
        CloudHsmAesGcmDecryptBufferedCipher cipher = new CloudHsmAesGcmDecryptBufferedCipher(innerMock.Object, aesKey, 128, null);
        
        byte[] result = cipher.DoFinal(combined, 0, 15);
        
        CollectionAssert.AreEqual(new byte[] { 3, 3, 3 }, result);
        innerMock.Verify(m => m.Init(false, It.Is<AeadParameters>(p => p.GetNonce().SequenceEqual(iv))), Times.Once);
    }

    [TestMethod]
    public void Wrap_PrependsIv()
    {
        byte[] iv = new byte[12];
        new SecureRandom().NextBytes(iv);
        SecureRandom random = new SecureRandom();
        
        AesKeyObject wrappingKey = new AesKeyObject();
        wrappingKey.SetSecret(new byte[16]);
        wrappingKey.CkaWrap = true;
        
        CloudHsmAesGcmWrapper wrapper = new CloudHsmAesGcmWrapper(wrappingKey, 128, iv, null, CKM.CKM_CLOUDHSM_AES_GCM, random);
        wrapper.Init(true, null);
        
        byte[] keyToWrap = new byte[32]; // e.g. AES-256 key
        random.NextBytes(keyToWrap);
        
        byte[] wrapped = wrapper.Wrap(keyToWrap, 0, keyToWrap.Length);
        
        Assert.AreEqual(12 + 32 + 16, wrapped.Length); // IV + Key + Tag
        CollectionAssert.AreEqual(iv, wrapped.Take(12).ToArray());
    }

    [TestMethod]
    public void Unwrap_ExtractsIv()
    {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.NextBytes(iv);
        
        AesKeyObject wrappingKey = new AesKeyObject();
        wrappingKey.SetSecret(new byte[16]);
        wrappingKey.CkaWrap = true;
        wrappingKey.CkaUnwrap = true;
        
        CloudHsmAesGcmWrapper wrapper = new CloudHsmAesGcmWrapper(wrappingKey, 128, iv, null, CKM.CKM_CLOUDHSM_AES_GCM, random);
        wrapper.Init(true, null);
        
        byte[] keyToWrap = new byte[32];
        random.NextBytes(keyToWrap);
        
        byte[] wrapped = wrapper.Wrap(keyToWrap, 0, keyToWrap.Length);
        
        // Now unwrap
        wrapper.Init(false, null);
        byte[] unwrapped = wrapper.Unwrap(wrapped, 0, wrapped.Length);
        
        CollectionAssert.AreEqual(keyToWrap, unwrapped);
    }
}
