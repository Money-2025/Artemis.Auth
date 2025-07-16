namespace Artemis.Auth.Api.DTOs.User;

/// <summary>
/// User session response DTO
/// </summary>
public class UserSessionResponse
{
    /// <summary>
    /// Session ID
    /// </summary>
    public Guid SessionId { get; set; }

    /// <summary>
    /// Device information
    /// </summary>
    public string DeviceInfo { get; set; } = string.Empty;

    /// <summary>
    /// IP address
    /// </summary>
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// User agent
    /// </summary>
    public string UserAgent { get; set; } = string.Empty;

    /// <summary>
    /// Location information
    /// </summary>
    public string? Location { get; set; }

    /// <summary>
    /// Session creation time
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last activity time
    /// </summary>
    public DateTime LastActivity { get; set; }

    /// <summary>
    /// Session expiration time
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Whether this is the current session
    /// </summary>
    public bool IsCurrent { get; set; }

    /// <summary>
    /// Whether session is active
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Session duration
    /// </summary>
    public TimeSpan Duration => DateTime.UtcNow - CreatedAt;

    /// <summary>
    /// Time until expiration
    /// </summary>
    public TimeSpan? TimeUntilExpiration => ExpiresAt > DateTime.UtcNow ? ExpiresAt - DateTime.UtcNow : null;

    /// <summary>
    /// Device type (Mobile, Desktop, Tablet, etc.)
    /// </summary>
    public string DeviceType { get; set; } = string.Empty;

    /// <summary>
    /// Operating system
    /// </summary>
    public string OperatingSystem { get; set; } = string.Empty;

    /// <summary>
    /// Browser information
    /// </summary>
    public string Browser { get; set; } = string.Empty;

    /// <summary>
    /// Whether device is trusted
    /// </summary>
    public bool IsTrusted { get; set; }

    /// <summary>
    /// Last login method
    /// </summary>
    public string LoginMethod { get; set; } = string.Empty;

    /// <summary>
    /// Two-factor authentication used
    /// </summary>
    public bool TwoFactorUsed { get; set; }
}

/// <summary>
/// User sessions list response DTO
/// </summary>
public class UserSessionsResponse
{
    /// <summary>
    /// List of active sessions
    /// </summary>
    public List<UserSessionResponse> Sessions { get; set; } = new();

    /// <summary>
    /// Total number of sessions
    /// </summary>
    public int TotalSessions { get; set; }

    /// <summary>
    /// Number of active sessions
    /// </summary>
    public int ActiveSessions { get; set; }

    /// <summary>
    /// Current session ID
    /// </summary>
    public Guid CurrentSessionId { get; set; }

    /// <summary>
    /// Last activity time
    /// </summary>
    public DateTime LastActivity { get; set; }

    /// <summary>
    /// Session security summary
    /// </summary>
    public SessionSecuritySummary SecuritySummary { get; set; } = new();
}

/// <summary>
/// Session security summary
/// </summary>
public class SessionSecuritySummary
{
    /// <summary>
    /// Number of trusted devices
    /// </summary>
    public int TrustedDevices { get; set; }

    /// <summary>
    /// Number of unknown devices
    /// </summary>
    public int UnknownDevices { get; set; }

    /// <summary>
    /// Number of suspicious sessions
    /// </summary>
    public int SuspiciousSessions { get; set; }

    /// <summary>
    /// Last security event
    /// </summary>
    public DateTime? LastSecurityEvent { get; set; }

    /// <summary>
    /// Security recommendations
    /// </summary>
    public List<string> SecurityRecommendations { get; set; } = new();
}