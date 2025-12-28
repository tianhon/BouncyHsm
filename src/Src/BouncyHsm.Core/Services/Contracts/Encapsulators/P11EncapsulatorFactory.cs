using BouncyHsm.Core.Rpc;
using BouncyHsm.Core.Services.Contracts.P11;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;

namespace BouncyHsm.Core.Services.Contracts.Encapsulators;

internal static class P11EncapsulatorFactory
{
    public static IP11Encapsulator Create(MechanismValue mechanism, ILoggerFactory loggerFactory)
    {
        CKM mechanismType = (CKM)mechanism.MechanismType;

        return mechanismType switch
        {
            CKM.CKM_ML_KEM => new MlKemP11Encapsulator(loggerFactory.CreateLogger<MlKemP11Encapsulator>()),
            CKM.CKM_RSA_PKCS => new RsaP11Encapsulator(CipherUtilities.GetCipher("RSA//PKCS1PADDING"),
                loggerFactory.CreateLogger<RsaP11Encapsulator>(),
                mechanismType),
            _ => throw new RpcPkcs11Exception(CKR.CKR_MECHANISM_INVALID, $"Mechanism {mechanismType} is not supported for encapsulation."),
        };
    }
}