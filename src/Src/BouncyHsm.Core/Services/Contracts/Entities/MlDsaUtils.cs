using BouncyHsm.Core.Services.Contracts.P11;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BouncyHsm.Core.Services.Contracts.Entities;

internal static class MlDsaUtils
{
    public static CKP GetMlDsaparametersType(MLDsaParameters parameters)
    {
        if (parameters.Name == MLDsaParameters.ml_dsa_44.Name)
        {
            return CKP.CKP_ML_DSA_44;
        }

        if (parameters.Name == MLDsaParameters.ml_dsa_65.Name)
        {
            return CKP.CKP_ML_DSA_65;
        }

        if (parameters.Name == MLDsaParameters.ml_dsa_87.Name)
        {
            return CKP.CKP_ML_DSA_87;
        }

        throw new ArgumentException($"Unsupported ML DSA parameters '{parameters.Name}'.", nameof(parameters));
    }

    public static MLDsaParameters GetParametersFromType(CKP ckp)
    {
        return ckp switch
        {
            CKP.CKP_ML_DSA_44 => MLDsaParameters.ml_dsa_44,
            CKP.CKP_ML_DSA_65 => MLDsaParameters.ml_dsa_65,
            CKP.CKP_ML_DSA_87 => MLDsaParameters.ml_dsa_87,
            _ => throw new InvalidProgramException($"Unsupported ML DSA parameters type {ckp}."),
        };
    }

    public static string GetParametersName(CKP ckp)
    {
        return ckp switch
        {
            CKP.CKP_ML_DSA_44 => "ML-DSA-44",
            CKP.CKP_ML_DSA_65 => "ML-DSA-65",
            CKP.CKP_ML_DSA_87 => "ML-DSA-87",
            _ => throw new InvalidProgramException($"Unsupported ML DSA parameters type {ckp}."),
        };
    }

    public static string GetSignatureAlgorithmName(CKP ckp)
    {
        return GetParametersFromType(ckp).Name;
    }
}
