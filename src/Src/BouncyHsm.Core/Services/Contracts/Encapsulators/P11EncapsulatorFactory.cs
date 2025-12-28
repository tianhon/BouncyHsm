using BouncyHsm.Core.Rpc;
using BouncyHsm.Core.Services.Contracts.P11;
using BouncyHsm.Core.Services.P11Handlers.Common;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;

namespace BouncyHsm.Core.Services.Contracts.Encapsulators;

internal class P11EncapsulatorFactory
{
    private readonly ILoggerFactory loggerFactory;
    private readonly ILogger<P11EncapsulatorFactory> logger;

    public P11EncapsulatorFactory(ILoggerFactory loggerFactory)
    {
        this.loggerFactory = loggerFactory;
        this.logger = loggerFactory.CreateLogger<P11EncapsulatorFactory>();
    }

    public IP11Encapsulator Create(MechanismValue mechanism)
    {
        CKM mechanismType = (CKM)mechanism.MechanismType;

        return mechanismType switch
        {
            CKM.CKM_ML_KEM => new MlKemP11Encapsulator(this.loggerFactory.CreateLogger<MlKemP11Encapsulator>()),
            CKM.CKM_RSA_PKCS => new RsaP11Encapsulator(CipherUtilities.GetCipher("RSA//PKCS1PADDING"),
                this.loggerFactory.CreateLogger<RsaP11Encapsulator>(),
                mechanismType),
            CKM.CKM_RSA_PKCS_OAEP => this.CreateRsaOaep(mechanism),
            _ => throw new RpcPkcs11Exception(CKR.CKR_MECHANISM_INVALID, $"Mechanism {mechanismType} is not supported for encapsulation."),
        };
    }

    private RsaP11Encapsulator CreateRsaOaep(MechanismValue mechanism)
    {
        try
        {
            Ckp_CkRsaPkcsOaepParams rsaPkcsOaepParams = MessagePack.MessagePackSerializer.Deserialize<Ckp_CkRsaPkcsOaepParams>(mechanism.MechanismParamMp, MessagepackBouncyHsmResolver.GetOptions());

            if (this.logger.IsEnabled(LogLevel.Trace))
            {
                this.logger.LogTrace("Using RSA OAEP params with hashAlg {hashAlg}, mgf {mgf}, source {source}, source data len {sourceDataLen}.",
                    (CKM)rsaPkcsOaepParams.HashAlg,
                    (CKG)rsaPkcsOaepParams.Mgf,
                    (CKZ)rsaPkcsOaepParams.Source,
                    rsaPkcsOaepParams.SourceData?.Length ?? 0);
            }


            IDigest? hashAlg = DigestUtils.TryGetDigest((CKM)rsaPkcsOaepParams.HashAlg);
            if (hashAlg == null)
            {
                throw new RpcPkcs11Exception(CKR.CKR_MECHANISM_PARAM_INVALID, $"Invalid hashAlg {(CKM)rsaPkcsOaepParams.Mgf} in CK_RSA_PKCS_OAEP_PARAMS (mechanism CKM_RSA_PKCS_OAEP).");
            }

            IDigest? mgf = DigestUtils.TryGetDigest((CKG)rsaPkcsOaepParams.Mgf);
            if (mgf == null)
            {
                throw new RpcPkcs11Exception(CKR.CKR_MECHANISM_PARAM_INVALID, $"Invalid mgf {(CKG)rsaPkcsOaepParams.Mgf} in CK_RSA_PKCS_OAEP_PARAMS (mechanism CKM_RSA_PKCS_OAEP).");
            }

            RsaBlindedEngine rsa = new RsaBlindedEngine();
            OaepEncoding rsaOpeap = new OaepEncoding(rsa, hashAlg, mgf, rsaPkcsOaepParams.SourceData);
            BufferedAsymmetricBlockCipher bufferedCipher = new BufferedAsymmetricBlockCipher(rsaOpeap);

            return new RsaP11Encapsulator(bufferedCipher,
                this.loggerFactory.CreateLogger<RsaP11Encapsulator>(),
                CKM.CKM_RSA_PKCS_OAEP);
        }
        catch (RpcPkcs11Exception)
        {
            throw;
        }
        catch (Exception ex)
        {
            this.logger.LogError(ex, "Error in builds {MechanismType} from parameter.", (CKM)mechanism.MechanismType);
            throw new RpcPkcs11Exception(CKR.CKR_MECHANISM_PARAM_INVALID, $"Invalid parameter for mechanism {(CKM)mechanism.MechanismType}.", ex);
        }
    }
}