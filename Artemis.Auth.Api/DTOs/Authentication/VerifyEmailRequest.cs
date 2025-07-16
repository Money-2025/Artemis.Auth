using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Authentication;

/// <summary>
/// Email verification request DTO
/// </summary>
public class VerifyEmailRequest
{
    /// <summary>
    /// Email address to verify
    /// </summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Email verification token
    /// </summary>
    [Required(ErrorMessage = "Verification token is required")]
    public string Token { get; set; } = string.Empty;

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
/// Email verification response DTO
/// </summary>
public class VerifyEmailResponse
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
    /// Whether account is now active
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Whether automatic login is performed
    /// </summary>
    public bool AutoLogin { get; set; } = false;

    /// <summary>
    /// Login information (if auto-login is enabled)
    /// </summary>
    public LoginResponse? LoginResponse { get; set; }

    /// <summary>
    /// Verification timestamp
    /// </summary>
    public DateTime VerifiedAt { get; set; } = DateTime.UtcNow;
}