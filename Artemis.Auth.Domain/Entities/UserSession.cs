namespace Artemis.Auth.Domain.Entities;

public class UserSession : AuditableEntity
{
    public string SessionTokenHash { get; set; } = string.Empty;
    public DateTime? LastAccessAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? CountryCode { get; set; }
    public string? DeviceFingerprint { get; set; }
    public bool IsRevoked { get; set; } = false;
    public DateTime? RevokedAt { get; set; }
    public Guid? RevokedBy { get; set; }
    
    // Many-to-one relationship
    public Guid UserId { get; set; }
    public virtual User User { get; set; }
}