using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Authentication;

/// <summary>
/// Refresh token request DTO
/// </summary>
public class RefreshTokenRequest
{
    /// <summary>
    /// Access token to refresh
    /// </summary>
    [Required(ErrorMessage = "Access token is required")]
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Refresh token
    /// </summary>
    [Required(ErrorMessage = "Refresh token is required")]
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Device information for validation
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