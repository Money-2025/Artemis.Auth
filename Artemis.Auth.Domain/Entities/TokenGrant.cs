using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Domain.Entities;

public class TokenGrant : AuditableEntity
{
    // Many-to-one relationship (Foreign Key)
    public Guid UserId { get; set; }
    
    public TokenType TokenType { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }
    
    // Many-to-one relationship
    public virtual User User { get; set; } = null!;
}