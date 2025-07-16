using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Mfa;

/// <summary>
/// MFA verification request DTO
/// </summary>
public class MfaVerifyRequest
{
    /// <summary>
    /// MFA code to verify
    /// </summary>
    [Required(ErrorMessage = "MFA code is required")]
    [StringLength(10, MinimumLength = 6, ErrorMessage = "MFA code must be between 6 and 10 characters")]
    public string Code { get; set; } = string.Empty;

    /// <summary>
    /// MFA method type
    /// </summary>
    [Required(ErrorMessage = "MFA method is required")]
    public string Method { get; set; } = string.Empty;

    /// <summary>
    /// Setup token (for initial setup verification)
    /// </summary>
    public string? SetupToken { get; set; }

    /// <summary>
    /// Whether to remember this device
    /// </summary>
    public bool RememberDevice { get; set; } = false;

    /// <summary>
    /// Device name for trusted devices
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
/// MFA verification response DTO
/// </summary>
public class MfaVerifyResponse
{
    /// <summary>
    /// Verification success flag
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Response message
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Whether MFA setup is now complete
    /// </summary>
    public bool SetupComplete { get; set; }

    /// <summary>
    /// Whether device is now trusted
    /// </summary>
    public bool DeviceTrusted { get; set; }

    /// <summary>
    /// Trusted device token
    /// </summary>
    public string? TrustedDeviceToken { get; set; }

    /// <summary>
    /// Verification timestamp
    /// </summary>
    public DateTime VerifiedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Remaining backup codes count
    /// </summary>
    public int RemainingBackupCodes { get; set; }

    /// <summary>
    /// Next verification required after
    /// </summary>
    public DateTime? NextVerificationRequired { get; set; }
}