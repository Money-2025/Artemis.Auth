using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Authentication;

/// <summary>
/// Forgot password request DTO
/// </summary>
public class ForgotPasswordRequest
{
    /// <summary>
    /// Email address for password reset
    /// </summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email must not exceed 256 characters")]
    public string Email { get; set; } = string.Empty;

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
/// Forgot password response DTO
/// </summary>
public class ForgotPasswordResponse
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
    /// Email sent flag
    /// </summary>
    public bool EmailSent { get; set; }

    /// <summary>
    /// Token expiration time (for testing environments only)
    /// </summary>
    public DateTime? TokenExpiresAt { get; set; }
}