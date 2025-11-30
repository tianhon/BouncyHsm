using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Pkcs11Interop.Ext;
using Pkcs11Interop.Ext.HighLevelAPI.MechanismParams;
using System.Security.Cryptography;

namespace BouncyHsm.Pkcs11IntegrationTests;

[TestClass]
public class T21_VerifyMlDsa
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
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_44)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_65)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_87)]
    public void VerifyMlDsa_WithoutParameters_Success(uint ckp)
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

        string label = $"MlDsaTest-{DateTime.UtcNow}-{RandomNumberGenerator.GetInt32(100, 999)}";
        byte[] ckId = session.GenerateRandom(32);

        CreateEcdsaKeyPair(ckp, factories, ckId, label, false, session, out IObjectHandle publicKey, out IObjectHandle privateKey);


        using IMechanism mechanism = factories.MechanismFactory.Create(CKM_V3_2.CKM_ML_DSA);
        byte[] signature = session.Sign(mechanism, privateKey, dataToSign);

        session.Verify(mechanism, publicKey, dataToSign, signature, out bool isValid);

        Assert.IsTrue(isValid, "Signature is not valid.");

        dataToSign[3] ^= 0xFF;

        session.Verify(mechanism, publicKey, dataToSign, signature, out isValid);

        Assert.IsFalse(isValid, "Signature is valid.");
    }

    [TestMethod]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_44, true, 0)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_65, true, 0)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_87, true, 0)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_44, false, 0)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_65, false, 0)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_87, false, 0)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_44, true, 16)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_65, true, 32)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_87, true, 143)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_44, false, 32)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_65, false, 12)]
    [DataRow(CK_ML_DSA_PARAMETER_SET.CKP_ML_DSA_87, false, 8)]
    public void VerifyMlDsa_WithParameters_Success(uint ckp, bool deterministic, int contextLength)
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

        string label = $"MlDsaTest-{DateTime.UtcNow}-{RandomNumberGenerator.GetInt32(100, 999)}";
        byte[] ckId = session.GenerateRandom(32);

        CreateEcdsaKeyPair(ckp, factories, ckId, label, false, session, out IObjectHandle publicKey, out IObjectHandle privateKey);

        using ICkSignAdditionalContextParams parameters = Pkcs11V3_0Factory.Instance.MechanismParamsFactory.CreateSignAdditionalContextParams(
              deterministic ? CKH_DETERMINISTIC_REQUIRED : CKH_HEDGE_REQUIRED,
              dataContent);
        using IMechanism mechanism = factories.MechanismFactory.Create(CKM_V3_2.CKM_ML_DSA, parameters);
        byte[] signature = session.Sign(mechanism, privateKey, dataToSign);

        session.Verify(mechanism, publicKey, dataToSign, signature, out bool isValid);

        Assert.IsTrue(isValid, "Signature is not valid.");

        dataToSign[3] ^= 0xFF;

        session.Verify(mechanism, publicKey, dataToSign, signature, out isValid);

        Assert.IsFalse(isValid, "Signature is valid.");
    }

    private static void CreateEcdsaKeyPair(uint ckp, Pkcs11InteropFactories factories, byte[] ckId, string label, bool token, ISession session, out IObjectHandle publicKey, out IObjectHandle privateKey)
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

        using IMechanism mechanism = factories.MechanismFactory.Create(CKM_V3_2.CKM_ML_DSA_KEY_PAIR_GEN);
        session.GenerateKeyPair(mechanism,
            publicKeyAttributes,
            privateKeyAttributes,
            out publicKey,
            out privateKey);
    }
}