using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Mfa;

/// <summary>
/// MFA setup request DTO
/// </summary>
public class MfaSetupRequest
{
    /// <summary>
    /// MFA method type (TOTP, SMS, Email)
    /// </summary>
    [Required(ErrorMessage = "MFA method is required")]
    public string Method { get; set; } = string.Empty;

    /// <summary>
    /// Phone number for SMS MFA
    /// </summary>
    [Phone(ErrorMessage = "Invalid phone number format")]
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Email address for Email MFA
    /// </summary>
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string? EmailAddress { get; set; }

    /// <summary>
    /// Device name for TOTP
    /// </summary>
    [StringLength(50, ErrorMessage = "Device name must not exceed 50 characters")]
    public string? DeviceName { get; set; }

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
/// MFA setup response DTO
/// </summary>
public class MfaSetupResponse
{
    /// <summary>
    /// Setup success flag
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Response message
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// MFA method type
    /// </summary>
    public string Method { get; set; } = string.Empty;

    /// <summary>
    /// QR code for TOTP setup
    /// </summary>
    public string? QrCode { get; set; }

    /// <summary>
    /// Manual entry key for TOTP
    /// </summary>
    public string? ManualEntryKey { get; set; }

    /// <summary>
    /// Backup codes
    /// </summary>
    public List<string> BackupCodes { get; set; } = new();

    /// <summary>
    /// Setup completion required
    /// </summary>
    public bool RequiresVerification { get; set; } = true;

    /// <summary>
    /// Setup token for verification
    /// </summary>
    public string? SetupToken { get; set; }

    /// <summary>
    /// Expiration time for setup token
    /// </summary>
    public DateTime? SetupExpiresAt { get; set; }

    /// <summary>
    /// Next step instructions
    /// </summary>
    public List<string> NextSteps { get; set; } = new();
}