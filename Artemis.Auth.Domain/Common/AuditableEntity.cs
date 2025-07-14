using Artemis.Auth.Domain.Common;

namespace Artemis.Auth.Domain.Entities;

public abstract class AuditableEntity : ISoftDeletable
{
    public Guid Id { get; set; }
    public bool IsDeleted { get; set; }
    public DateTime? DeletedAt { get; set; }
    public Guid? DeletedBy { get; set; }
    public DateTime CreatedAt { get; set; }
    public Guid? CreatedBy { get; set; }
    public DateTime? ModifiedAt { get; set; }
    public Guid? ModifiedBy { get; set; }
    public long RowVersion { get; set; }
}