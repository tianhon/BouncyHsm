using BouncyHsm.Core.Services.Contracts.P11;

namespace BouncyHsm.Core.UseCases.Contracts;

public class GenerateMLDsaKeyPairRequest
{
    public CKP MlDsaParameter
    {
        get;
        set;
    }

    public GenerateKeyAttributes KeyAttributes
    {
        get;
        set;
    }

    public GenerateMLDsaKeyPairRequest()
    {
        this.KeyAttributes = new GenerateKeyAttributes();
    }
}