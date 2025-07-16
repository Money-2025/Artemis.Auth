namespace Artemis.Auth.Api.DTOs.Authentication;

/// <summary>
/// Login response DTO with comprehensive authentication information
/// </summary>
public class LoginResponse
{
    /// <summary>
    /// JWT access token
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// JWT refresh token
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Token type (Bearer)
    /// </summary>
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// Token expiration time in seconds
    /// </summary>
    public int ExpiresIn { get; set; }

    /// <summary>
    /// User information
    /// </summary>
    public UserInfo User { get; set; } = new();

    /// <summary>
    /// Whether two-factor authentication is required
    /// </summary>
    public bool RequiresTwoFactor { get; set; } = false;

    /// <summary>
    /// Available two-factor methods
    /// </summary>
    public List<string> TwoFactorMethods { get; set; } = new();

    /// <summary>
    /// Whether email verification is required
    /// </summary>
    public bool RequiresEmailVerification { get; set; } = false;

    /// <summary>
    /// Session information
    /// </summary>
    public SessionInfo Session { get; set; } = new();
}

/// <summary>
/// User information for login response
/// </summary>
public class UserInfo
{
    /// <summary>
    /// User ID
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Username
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Email address
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// First name
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// Last name
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// User roles
    /// </summary>
    public List<string> Roles { get; set; } = new();

    /// <summary>
    /// User permissions
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Whether email is confirmed
    /// </summary>
    public bool EmailConfirmed { get; set; }

    /// <summary>
    /// Whether two-factor authentication is enabled
    /// </summary>
    public bool TwoFactorEnabled { get; set; }

    /// <summary>
    /// Last login time
    /// </summary>
    public DateTime? LastLogin { get; set; }
}

/// <summary>
/// Session information for login response
/// </summary>
public class SessionInfo
{
    /// <summary>
    /// Session ID
    /// </summary>
    public Guid SessionId { get; set; }

    /// <summary>
    /// Session creation time
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Session expiration time
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Device information
    /// </summary>
    public string DeviceInfo { get; set; } = string.Empty;

    /// <summary>
    /// IP address
    /// </summary>
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// Location information
    /// </summary>
    public string Location { get; set; } = string.Empty;
}