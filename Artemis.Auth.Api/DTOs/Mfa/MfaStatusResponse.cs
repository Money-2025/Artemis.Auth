using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Mfa;

/// <summary>
/// MFA status response DTO
/// </summary>
public class MfaStatusResponse
{
    /// <summary>
    /// Whether MFA is enabled
    /// </summary>
    public bool IsEnabled { get; set; }

    /// <summary>
    /// Whether MFA is required for this user
    /// </summary>
    public bool IsRequired { get; set; }

    /// <summary>
    /// Available MFA methods
    /// </summary>
    public List<MfaMethodInfo> AvailableMethods { get; set; } = new();

    /// <summary>
    /// Configured MFA methods
    /// </summary>
    public List<MfaMethodInfo> ConfiguredMethods { get; set; } = new();

    /// <summary>
    /// Primary MFA method
    /// </summary>
    public string? PrimaryMethod { get; set; }

    /// <summary>
    /// Backup methods enabled
    /// </summary>
    public bool BackupMethodsEnabled { get; set; }

    /// <summary>
    /// Number of backup codes remaining
    /// </summary>
    public int BackupCodesRemaining { get; set; }

    /// <summary>
    /// Trusted devices count
    /// </summary>
    public int TrustedDevicesCount { get; set; }

    /// <summary>
    /// Last MFA verification
    /// </summary>
    public DateTime? LastVerification { get; set; }

    /// <summary>
    /// MFA setup date
    /// </summary>
    public DateTime? SetupDate { get; set; }

    /// <summary>
    /// Security recommendations
    /// </summary>
    public List<string> SecurityRecommendations { get; set; } = new();
}

/// <summary>
/// MFA method information
/// </summary>
public class MfaMethodInfo
{
    /// <summary>
    /// Method type (TOTP, SMS, Email)
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Method display name
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Method description
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Whether method is enabled
    /// </summary>
    public bool IsEnabled { get; set; }

    /// <summary>
    /// Whether method is configured
    /// </summary>
    public bool IsConfigured { get; set; }

    /// <summary>
    /// Whether method is primary
    /// </summary>
    public bool IsPrimary { get; set; }

    /// <summary>
    /// Method configuration details (masked)
    /// </summary>
    public string? ConfigurationDetails { get; set; }

    /// <summary>
    /// Last used date
    /// </summary>
    public DateTime? LastUsed { get; set; }

    /// <summary>
    /// Setup date
    /// </summary>
    public DateTime? SetupDate { get; set; }

    /// <summary>
    /// Method-specific settings
    /// </summary>
    public Dictionary<string, object> Settings { get; set; } = new();
}

/// <summary>
/// MFA backup codes response DTO
/// </summary>
public class MfaBackupCodesResponse
{
    /// <summary>
    /// Backup codes
    /// </summary>
    public List<string> BackupCodes { get; set; } = new();

    /// <summary>
    /// Generation timestamp
    /// </summary>
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Expiration date
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Usage instructions
    /// </summary>
    public List<string> Instructions { get; set; } = new();

    /// <summary>
    /// Security warnings
    /// </summary>
    public List<string> SecurityWarnings { get; set; } = new();
}

/// <summary>
/// MFA disable request DTO
/// </summary>
public class MfaDisableRequest
{
    /// <summary>
    /// Current password for security confirmation
    /// </summary>
    [Required(ErrorMessage = "Current password is required")]
    public string CurrentPassword { get; set; } = string.Empty;

    /// <summary>
    /// MFA code for final verification
    /// </summary>
    [Required(ErrorMessage = "MFA code is required")]
    [StringLength(10, MinimumLength = 6, ErrorMessage = "MFA code must be between 6 and 10 characters")]
    public string MfaCode { get; set; } = string.Empty;

    /// <summary>
    /// Reason for disabling MFA
    /// </summary>
    [StringLength(200, ErrorMessage = "Reason must not exceed 200 characters")]
    public string? Reason { get; set; }

    /// <summary>
    /// Client IP address (set by middleware)
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent (set by middleware)
    /// </summary>
    public string? UserAgent { get; set; }
}

/// <summary>
/// MFA disable response DTO
/// </summary>
public class MfaDisableResponse
{
    /// <summary>
    /// Success flag
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Response message
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Disabled timestamp
    /// </summary>
    public DateTime DisabledAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Security warnings
    /// </summary>
    public List<string> SecurityWarnings { get; set; } = new();

    /// <summary>
    /// Whether re-authentication is required
    /// </summary>
    public bool RequiresReauth { get; set; } = true;
}