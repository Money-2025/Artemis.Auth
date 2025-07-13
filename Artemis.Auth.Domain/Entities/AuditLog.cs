using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Domain.Entities;

public class AuditLog : AuditableEntity
{
    public string TableName { get; set; } = string.Empty;
    public Guid RecordId { get; set; }
    public AuditAction Action { get; set; }
    public string? OldData { get; set; }
    public string? NewData { get; set; }
    public DateTime PerformedAt { get; set; } = DateTime.UtcNow;
    
    // Many-to-one relationship (for 'performed_by')
    public Guid? PerformedBy { get; set; } // This is the foreign key property
    public virtual User User { get; set; }
}