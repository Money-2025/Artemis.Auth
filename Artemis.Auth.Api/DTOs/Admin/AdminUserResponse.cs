namespace Artemis.Auth.Api.DTOs.Admin;

/// <summary>
/// Admin user response DTO with comprehensive user information
/// </summary>
public class AdminUserResponse
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
    /// Full name
    /// </summary>
    public string FullName => $"{FirstName} {LastName}".Trim();

    /// <summary>
    /// Phone number
    /// </summary>
    public string? PhoneNumber { get; set; }

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
    /// Whether phone is confirmed
    /// </summary>
    public bool PhoneConfirmed { get; set; }

    /// <summary>
    /// Whether two-factor authentication is enabled
    /// </summary>
    public bool TwoFactorEnabled { get; set; }

    /// <summary>
    /// Whether account is locked
    /// </summary>
    public bool IsLocked { get; set; }

    /// <summary>
    /// Account lockout end time
    /// </summary>
    public DateTime? LockoutEnd { get; set; }

    /// <summary>
    /// Failed login attempts
    /// </summary>
    public int FailedLoginAttempts { get; set; }

    /// <summary>
    /// Account creation date
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last profile update
    /// </summary>
    public DateTime UpdatedAt { get; set; }

    /// <summary>
    /// Last login time
    /// </summary>
    public DateTime? LastLogin { get; set; }

    /// <summary>
    /// Whether account is soft deleted
    /// </summary>
    public bool IsDeleted { get; set; }

    /// <summary>
    /// Account deletion date
    /// </summary>
    public DateTime? DeletedAt { get; set; }

    /// <summary>
    /// User activity summary
    /// </summary>
    public UserActivitySummary ActivitySummary { get; set; } = new();

    /// <summary>
    /// User security summary
    /// </summary>
    public UserSecuritySummary SecuritySummary { get; set; } = new();
}

/// <summary>
/// User activity summary
/// </summary>
public class UserActivitySummary
{
    /// <summary>
    /// Total login count
    /// </summary>
    public int TotalLogins { get; set; }

    /// <summary>
    /// Successful login count
    /// </summary>
    public int SuccessfulLogins { get; set; }

    /// <summary>
    /// Failed login count
    /// </summary>
    public int FailedLogins { get; set; }

    /// <summary>
    /// Last 30 days login count
    /// </summary>
    public int LoginsLast30Days { get; set; }

    /// <summary>
    /// Average session duration
    /// </summary>
    public TimeSpan AverageSessionDuration { get; set; }

    /// <summary>
    /// Total session count
    /// </summary>
    public int TotalSessions { get; set; }

    /// <summary>
    /// Active session count
    /// </summary>
    public int ActiveSessions { get; set; }

    /// <summary>
    /// Password change count
    /// </summary>
    public int PasswordChanges { get; set; }

    /// <summary>
    /// Last password change
    /// </summary>
    public DateTime? LastPasswordChange { get; set; }
}

/// <summary>
/// User security summary
/// </summary>
public class UserSecuritySummary
{
    /// <summary>
    /// Security score (0-100)
    /// </summary>
    public int SecurityScore { get; set; }

    /// <summary>
    /// Whether using strong password
    /// </summary>
    public bool HasStrongPassword { get; set; }

    /// <summary>
    /// Whether MFA is enabled
    /// </summary>
    public bool MfaEnabled { get; set; }

    /// <summary>
    /// Number of trusted devices
    /// </summary>
    public int TrustedDevices { get; set; }

    /// <summary>
    /// Number of suspicious login attempts
    /// </summary>
    public int SuspiciousAttempts { get; set; }

    /// <summary>
    /// Last suspicious activity
    /// </summary>
    public DateTime? LastSuspiciousActivity { get; set; }

    /// <summary>
    /// Security recommendations
    /// </summary>
    public List<string> SecurityRecommendations { get; set; } = new();

    /// <summary>
    /// Account risk level
    /// </summary>
    public string RiskLevel { get; set; } = "Low";
}

/// <summary>
/// Admin users list response DTO
/// </summary>
public class AdminUsersResponse
{
    /// <summary>
    /// List of users
    /// </summary>
    public List<AdminUserResponse> Users { get; set; } = new();

    /// <summary>
    /// Total number of users
    /// </summary>
    public int TotalUsers { get; set; }

    /// <summary>
    /// Current page number
    /// </summary>
    public int CurrentPage { get; set; }

    /// <summary>
    /// Total number of pages
    /// </summary>
    public int TotalPages { get; set; }

    /// <summary>
    /// Page size
    /// </summary>
    public int PageSize { get; set; }

    /// <summary>
    /// Whether there are more pages
    /// </summary>
    public bool HasNextPage { get; set; }

    /// <summary>
    /// Whether there are previous pages
    /// </summary>
    public bool HasPreviousPage { get; set; }

    /// <summary>
    /// User statistics
    /// </summary>
    public UserStatistics Statistics { get; set; } = new();
}

/// <summary>
/// User statistics
/// </summary>
public class UserStatistics
{
    /// <summary>
    /// Total active users
    /// </summary>
    public int ActiveUsers { get; set; }

    /// <summary>
    /// Total locked users
    /// </summary>
    public int LockedUsers { get; set; }

    /// <summary>
    /// Total deleted users
    /// </summary>
    public int DeletedUsers { get; set; }

    /// <summary>
    /// Users with unconfirmed email
    /// </summary>
    public int UnconfirmedEmailUsers { get; set; }

    /// <summary>
    /// Users with MFA enabled
    /// </summary>
    public int MfaEnabledUsers { get; set; }

    /// <summary>
    /// New users today
    /// </summary>
    public int NewUsersToday { get; set; }

    /// <summary>
    /// New users this week
    /// </summary>
    public int NewUsersThisWeek { get; set; }

    /// <summary>
    /// New users this month
    /// </summary>
    public int NewUsersThisMonth { get; set; }

    /// <summary>
    /// Active users today
    /// </summary>
    public int ActiveUsersToday { get; set; }

    /// <summary>
    /// Active users this week
    /// </summary>
    public int ActiveUsersThisWeek { get; set; }

    /// <summary>
    /// Active users this month
    /// </summary>
    public int ActiveUsersThisMonth { get; set; }
}