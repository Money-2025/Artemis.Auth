namespace Artemis.Auth.Domain.Entities;

public class PasswordHistory : AuditableEntity
{
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime ChangedAt { get; set; }
    public Guid? ChangedBy { get; set; }
    public int PolicyVersion { get; set; }
    
    // Many-to-one relationship
    public Guid UserId { get; set; }
    public virtual User User { get; set; } = null!;
}