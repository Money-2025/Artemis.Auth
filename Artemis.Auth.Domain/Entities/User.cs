using Artemis.Auth.Domain.Common;

namespace Artemis.Auth.Domain.Entities;

public class User : AuditableEntity, IValidatable
{
    public string Username { get; set; } = string.Empty;
    public string NormalizedUsername { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string NormalizedEmail { get; set; } = string.Empty;
    public bool EmailConfirmed { get; set; }
    public string? PhoneNumber { get; set; }
    public bool PhoneNumberConfirmed { get; set; }
    public string PasswordHash { get; set; } = string.Empty;
    public string? SecurityStamp { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTime? LockoutEnd { get; set; }
    
    // One-to-many relationships
    public virtual ICollection<UserRole> UserRoles { get; set; } = new HashSet<UserRole>();
    public virtual ICollection<UserMfaMethod> UserMfaMethods { get; set; } = new HashSet<UserMfaMethod>();
    public virtual ICollection<TokenGrant> TokenGrants { get; set; } = new HashSet<TokenGrant>();
    public virtual ICollection<AuditLog> AuditLogs { get; set; } = new HashSet<AuditLog>();
    public virtual ICollection<UserSession> UserSessions { get; set; } = new HashSet<UserSession>();
    public virtual ICollection<PasswordHistory> PasswordHistories { get; set; } = new HashSet<PasswordHistory>();
    public virtual ICollection<DeviceTrust> DeviceTrusts { get; set; } = new HashSet<DeviceTrust>();
    
    // Validation
    public ValidationResult Validate()
    {
        var errors = new List<ValidationError>();
        
        // Username validation
        if (!Username.IsValidUsername())
        {
            errors.Add(new ValidationError(nameof(Username), "Username must be 3-50 characters long and contain only letters, numbers, underscores, hyphens, and dots."));
        }
        
        // Email validation
        if (!Email.IsValidEmail())
        {
            errors.Add(new ValidationError(nameof(Email), "Email address is not in a valid format."));
        }
        
        // Phone number validation (if provided)
        if (!string.IsNullOrWhiteSpace(PhoneNumber) && !PhoneNumber.IsValidPhoneNumber())
        {
            errors.Add(new ValidationError(nameof(PhoneNumber), "Phone number is not in a valid format."));
        }
        
        // Password hash validation
        if (string.IsNullOrWhiteSpace(PasswordHash))
        {
            errors.Add(new ValidationError(nameof(PasswordHash), "Password hash is required."));
        }
        
        // Security stamp validation
        if (string.IsNullOrWhiteSpace(SecurityStamp))
        {
            errors.Add(new ValidationError(nameof(SecurityStamp), "Security stamp is required."));
        }
        
        // Failed login count validation
        if (!FailedLoginCount.IsInRange(0, 10))
        {
            errors.Add(new ValidationError(nameof(FailedLoginCount), "Failed login count must be between 0 and 10."));
        }
        
        // Lockout validation
        if (LockoutEnd.HasValue && LockoutEnd < DateTime.UtcNow)
        {
            errors.Add(new ValidationError(nameof(LockoutEnd), "Lockout end time cannot be in the past."));
        }
        
        return errors.Count == 0 ? ValidationResult.Success() : ValidationResult.Failure(errors.ToArray());
    }
    
    // Business logic methods
    public bool IsLockedOut()
    {
        return LockoutEnd.HasValue && LockoutEnd.Value > DateTime.UtcNow;
    }
    
    public bool ShouldLockout(int maxFailedAttempts)
    {
        return FailedLoginCount >= maxFailedAttempts;
    }
    
    public void ResetFailedLoginCount()
    {
        FailedLoginCount = 0;
        LockoutEnd = null;
    }
    
    public void IncrementFailedLoginCount()
    {
        FailedLoginCount++;
        LastLoginAt = DateTime.UtcNow;
    }
    
    public void LockoutUser(TimeSpan lockoutDuration)
    {
        LockoutEnd = DateTime.UtcNow.Add(lockoutDuration);
    }
}