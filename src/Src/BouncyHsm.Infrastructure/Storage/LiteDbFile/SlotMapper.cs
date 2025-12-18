using BouncyHsm.Core.Services.Contracts;
using BouncyHsm.Core.Services.Contracts.Entities;
using BouncyHsm.Infrastructure.Storage.LiteDbFile.DbModels;
using Riok.Mapperly.Abstractions;

namespace BouncyHsm.Infrastructure.Storage.LiteDbFile;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName,
    EnumMappingIgnoreCase = false,
    ThrowOnMappingNullMismatch = true,
    ThrowOnPropertyMappingNullMismatch = true)]
internal partial class SlotMapper
{
    public SlotMapper()
    {

    }

    [MapperIgnoreTarget(nameof(SlotModel.Created))]
    [MapProperty(nameof(SlotModel.IsPlugged), nameof(SlotEntity.IsPlugged), Use = nameof(IsPluggedMapper))]
    public partial SlotModel MapSlot(SlotEntity slotEntity);


    [MapperIgnoreSource(nameof(SlotModel.Created))]
    public partial SlotEntity MapSlot(SlotModel model);

    [UserMapping(Default = false)]
    private bool IsPluggedMapper(bool? value)
    {
        return value ?? false;
    }
}