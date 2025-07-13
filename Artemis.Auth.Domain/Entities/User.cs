namespace Artemis.Auth.Domain.Entities;

public class User : AuditableEntity
{
    public string Username { get; set; } = string.Empty;
    public string NormalizedUsername { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string NormalizedEmail { get; set; } = string.Empty;
    public bool EmailConfirmed { get; set; } = false;
    public string? PhoneNumber { get; set; }
    public bool PhoneNumberConfirmed { get; set; } = false;
    public string PasswordHash { get; set; } = string.Empty;
    public string? SecurityStamp { get; set; }
    public bool TwoFactorEnabled { get; set; } = false;
    public DateTime? LastLoginAt { get; set; }
    public int FailedLoginCount { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }
    
    // One-to-many relationships
    public virtual ICollection<UserRole> UserRoles { get; set; } = new HashSet<UserRole>();
    public virtual ICollection<UserMfaMethod> UserMfaMethods { get; set; } = new HashSet<UserMfaMethod>();
    public virtual ICollection<TokenGrant> TokenGrants { get; set; } = new HashSet<TokenGrant>();
    public virtual ICollection<AuditLog> AuditLogs { get; set; } = new HashSet<AuditLog>();
    public virtual ICollection<UserSession> UserSessions { get; set; } = new HashSet<UserSession>();
    public virtual ICollection<PasswordHistory> PasswordHistories { get; set; } = new HashSet<PasswordHistory>();
    public virtual ICollection<DeviceTrust> DeviceTrusts { get; set; } = new HashSet<DeviceTrust>();
}