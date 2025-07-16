using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Authentication;

/// <summary>
/// Logout request DTO
/// </summary>
public class LogoutRequest
{
    /// <summary>
    /// Refresh token to invalidate
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Whether to logout from all devices
    /// </summary>
    public bool LogoutFromAllDevices { get; set; } = false;

    /// <summary>
    /// Device information
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

/// <summary>
/// Logout response DTO
/// </summary>
public class LogoutResponse
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
    /// Number of sessions terminated
    /// </summary>
    public int SessionsTerminated { get; set; }

    /// <summary>
    /// Logout timestamp
    /// </summary>
    public DateTime LogoutAt { get; set; } = DateTime.UtcNow;
}