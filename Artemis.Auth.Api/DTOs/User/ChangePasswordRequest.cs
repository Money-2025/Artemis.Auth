using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.User;

/// <summary>
/// Change password request DTO
/// </summary>
public class ChangePasswordRequest
{
    /// <summary>
    /// Current password
    /// </summary>
    [Required(ErrorMessage = "Current password is required")]
    [StringLength(128, ErrorMessage = "Current password must not exceed 128 characters")]
    public string CurrentPassword { get; set; } = string.Empty;

    /// <summary>
    /// New password
    /// </summary>
    [Required(ErrorMessage = "New password is required")]
    [StringLength(128, MinimumLength = 8, ErrorMessage = "New password must be between 8 and 128 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$", 
        ErrorMessage = "New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")]
    public string NewPassword { get; set; } = string.Empty;

    /// <summary>
    /// New password confirmation
    /// </summary>
    [Required(ErrorMessage = "Password confirmation is required")]
    [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    /// <summary>
    /// Whether to logout from all devices after password change
    /// </summary>
    public bool LogoutFromAllDevices { get; set; } = true;

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
/// Change password response DTO
/// </summary>
public class ChangePasswordResponse
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
    /// Whether sessions were terminated
    /// </summary>
    public bool SessionsTerminated { get; set; }

    /// <summary>
    /// Number of sessions terminated
    /// </summary>
    public int SessionsTerminatedCount { get; set; }

    /// <summary>
    /// Password change timestamp
    /// </summary>
    public DateTime ChangedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// New login required flag
    /// </summary>
    public bool RequiresNewLogin { get; set; } = true;
}