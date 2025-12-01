using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Pkcs11Interop.Ext;
using Pkcs11Interop.Ext.HighLevelAPI.MechanismParams;
using System.Security.Cryptography;

namespace BouncyHsm.Pkcs11IntegrationTests;

[TestClass]
public class T20_SignSlhDsa
{
    const ulong CKH_HEDGE_PREFERRED = 0x00000000;
    const ulong CKH_HEDGE_REQUIRED = 0x00000001;
    const ulong CKH_DETERMINISTIC_REQUIRED = 0x00000002;
    public TestContext? TestContext
    {
        get;
        set;
    }

    [TestMethod]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128S)]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128S)]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128F)]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128F)]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192S)]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192S)]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192F)]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192F)]
    [DataRow(Pkcs11Interop.Ext.Common.CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_256S)]
    public void SignSlhDsa_WithoutParameters_Success(uint ckp)
    {
        byte[] dataToSign = new byte[85];
        Random.Shared.NextBytes(dataToSign);

        Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
        using IPkcs11Library library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories,
            AssemblyTestConstants.P11LibPath,
            AppType.SingleThreaded);

        List<ISlot> slots = library.GetSlotList(SlotsType.WithTokenPresent);
        ISlot slot = slots.SelectTestSlot();

        using ISession session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, AssemblyTestConstants.UserPin);

        string label = $"SlhDsaTest-{DateTime.UtcNow}-{RandomNumberGenerator.GetInt32(100, 999)}";
        byte[] ckId = session.GenerateRandom(32);

        CreateSlhDsaKeyPair(ckp, factories, ckId, label, false, session, out IObjectHandle publicKey, out IObjectHandle privateKey);


        using IMechanism mechanism = factories.MechanismFactory.Create(CKM_V3_2.CKM_SLH_DSA);
        byte[] signature = session.Sign(mechanism, privateKey, dataToSign);

        Assert.IsNotNull(signature);
    }

    [TestMethod]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128S, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128S, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128F, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128F, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192S, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192S, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192F, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192F, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_256S, true, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128S, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128S, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128F, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128F, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192S, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192S, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192F, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192F, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_256S, false, 0)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128S, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128S, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128F, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128F, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192S, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192S, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192F, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192F, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_256S, true, 16)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128S, false, 32)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128S, false, 32)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_128F, false, 32)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_128F, false, 32)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192S, false, 32)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192S, false, 32)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_192F, false, 32)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHAKE_192F, false, 32)]
    [DataRow(CK_SLH_DSA_PARAMETER_SET.CKP_SLH_DSA_SHA2_256S, false, 32)]
    public void SignSlhDsa_WithParameters_Success(uint ckp, bool deterministic, int contextLength)
    {
        byte[] dataToSign = new byte[85];
        byte[]? dataContent = null;
        Random.Shared.NextBytes(dataToSign);

        if (contextLength > 0)
        {
            dataContent = new byte[contextLength];
            Random.Shared.NextBytes(dataContent);
        }

        Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
        using IPkcs11Library library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories,
            AssemblyTestConstants.P11LibPath,
            AppType.SingleThreaded);

        List<ISlot> slots = library.GetSlotList(SlotsType.WithTokenPresent);
        ISlot slot = slots.SelectTestSlot();

        using ISession session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, AssemblyTestConstants.UserPin);

        string label = $"SlhDsaTest-{DateTime.UtcNow}-{RandomNumberGenerator.GetInt32(100, 999)}";
        byte[] ckId = session.GenerateRandom(32);

        CreateSlhDsaKeyPair(ckp, factories, ckId, label, false, session, out IObjectHandle publicKey, out IObjectHandle privateKey);

        using ICkSignAdditionalContextParams parameters = Pkcs11V3_0Factory.Instance.MechanismParamsFactory.CreateSignAdditionalContextParams(
              deterministic ? CKH_DETERMINISTIC_REQUIRED : CKH_HEDGE_REQUIRED,
              dataContent);
        using IMechanism mechanism = factories.MechanismFactory.Create(CKM_V3_2.CKM_SLH_DSA, parameters);
        byte[] signature = session.Sign(mechanism, privateKey, dataToSign);

        Assert.IsNotNull(signature);
    }

    private static void CreateSlhDsaKeyPair(uint ckp, Pkcs11InteropFactories factories, byte[] ckId, string label, bool token, ISession session, out IObjectHandle publicKey, out IObjectHandle privateKey)
    {
        List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>()
        {
             factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, token),
            factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
            factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckId),
            factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, false),
            factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
            factories.ObjectAttributeFactory.Create(CKA_V3_2.CKA_PARAMETER_SET, ckp)
        };

        List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>()
        {
            factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, token),
            factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
            factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckId),
            factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false),
            factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true),
            factories.ObjectAttributeFactory.Create(CKA_V3_2.CKA_PARAMETER_SET, ckp)
        };

        using IMechanism mechanism = factories.MechanismFactory.Create(CKM_V3_2.CKM_SLH_DSA_KEY_PAIR_GEN);
        session.GenerateKeyPair(mechanism,
            publicKeyAttributes,
            privateKeyAttributes,
            out publicKey,
            out privateKey);
    }
}
