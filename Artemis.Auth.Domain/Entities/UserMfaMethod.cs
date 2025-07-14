using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Domain.Entities;

public class UserMfaMethod : AuditableEntity
{
    // Many-to-one relationships (Foreign Keys)
    public Guid UserId { get; set; }
    
    public MfaMethodType Type { get; set; }
    public string? SecretKey { get; set; }
    public bool IsEnabled { get; set; }
    
    public virtual User User { get; set; } = null!;
}