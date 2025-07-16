namespace Artemis.Auth.Api.DTOs.User;

/// <summary>
/// User profile response DTO
/// </summary>
public class UserProfileResponse
{
    /// <summary>
    /// User ID
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Username
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Email address
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// First name
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// Last name
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// Full name
    /// </summary>
    public string FullName => $"{FirstName} {LastName}".Trim();

    /// <summary>
    /// Phone number
    /// </summary>
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Date of birth
    /// </summary>
    public DateTime? DateOfBirth { get; set; }

    /// <summary>
    /// Profile picture URL
    /// </summary>
    public string? ProfilePictureUrl { get; set; }

    /// <summary>
    /// Bio or description
    /// </summary>
    public string? Bio { get; set; }

    /// <summary>
    /// Location
    /// </summary>
    public string? Location { get; set; }

    /// <summary>
    /// Website URL
    /// </summary>
    public string? WebsiteUrl { get; set; }

    /// <summary>
    /// Timezone
    /// </summary>
    public string? Timezone { get; set; }

    /// <summary>
    /// Language preference
    /// </summary>
    public string? Language { get; set; }

    /// <summary>
    /// User roles
    /// </summary>
    public List<string> Roles { get; set; } = new();

    /// <summary>
    /// User permissions
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Whether email is confirmed
    /// </summary>
    public bool EmailConfirmed { get; set; }

    /// <summary>
    /// Whether phone is confirmed
    /// </summary>
    public bool PhoneConfirmed { get; set; }

    /// <summary>
    /// Whether two-factor authentication is enabled
    /// </summary>
    public bool TwoFactorEnabled { get; set; }

    /// <summary>
    /// Account creation date
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last profile update
    /// </summary>
    public DateTime UpdatedAt { get; set; }

    /// <summary>
    /// Last login time
    /// </summary>
    public DateTime? LastLogin { get; set; }

    /// <summary>
    /// Whether account is locked
    /// </summary>
    public bool IsLocked { get; set; }

    /// <summary>
    /// Account lockout end time
    /// </summary>
    public DateTime? LockoutEnd { get; set; }

    /// <summary>
    /// Failed login attempts
    /// </summary>
    public int FailedLoginAttempts { get; set; }

    /// <summary>
    /// Marketing emails preference
    /// </summary>
    public bool AcceptMarketing { get; set; }

    /// <summary>
    /// Email notifications preference
    /// </summary>
    public bool EmailNotifications { get; set; }

    /// <summary>
    /// Push notifications preference
    /// </summary>
    public bool PushNotifications { get; set; }

    /// <summary>
    /// Account verification status
    /// </summary>
    public AccountVerificationStatus VerificationStatus { get; set; } = new();
}

/// <summary>
/// Account verification status
/// </summary>
public class AccountVerificationStatus
{
    /// <summary>
    /// Email verification status
    /// </summary>
    public bool EmailVerified { get; set; }

    /// <summary>
    /// Phone verification status
    /// </summary>
    public bool PhoneVerified { get; set; }

    /// <summary>
    /// Identity verification status
    /// </summary>
    public bool IdentityVerified { get; set; }

    /// <summary>
    /// Two-factor setup status
    /// </summary>
    public bool TwoFactorSetup { get; set; }

    /// <summary>
    /// Overall verification percentage
    /// </summary>
    public int VerificationPercentage
    {
        get
        {
            var verified = 0;
            var total = 4;

            if (EmailVerified) verified++;
            if (PhoneVerified) verified++;
            if (IdentityVerified) verified++;
            if (TwoFactorSetup) verified++;

            return (int)Math.Round((double)verified / total * 100);
        }
    }
}