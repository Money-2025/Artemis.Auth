namespace Artemis.Auth.Domain.Entities;

public class DeviceTrust : AuditableEntity
{
    public string? DeviceName { get; set; }
    public DateTime TrustedAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime? RevokedAt { get; set; }
    public Guid? RevokedBy { get; set; }
    
    // Many-to-one relationship
    public Guid UserId { get; set; }
    public virtual User User { get; set; } = null!;
}