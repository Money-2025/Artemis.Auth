using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Authentication;

/// <summary>
/// Login request DTO with comprehensive validation
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// Username or email address
    /// </summary>
    [Required(ErrorMessage = "Username or email is required")]
    [StringLength(256, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 256 characters")]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// User password
    /// </summary>
    [Required(ErrorMessage = "Password is required")]
    [StringLength(128, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 128 characters")]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Remember me flag for extended session
    /// </summary>
    public bool RememberMe { get; set; } = false;

    /// <summary>
    /// Two-factor authentication code (if enabled)
    /// </summary>
    [StringLength(10, MinimumLength = 6, ErrorMessage = "Two-factor code must be between 6 and 10 characters")]
    public string? TwoFactorCode { get; set; }

    /// <summary>
    /// Device information for tracking
    /// </summary>
    public string? DeviceInfo { get; set; }

    /// <summary>
    /// Client IP address (set by middleware)
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent (set by middleware)
    /// </summary>
    public string? UserAgent { get; set; }
}