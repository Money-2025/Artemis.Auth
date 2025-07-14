namespace Artemis.Auth.Infrastructure.Security;

public class SecurityConfiguration
{
    public PasswordPolicyOptions PasswordPolicy { get; set; } = new();
    public SessionOptions Session { get; set; } = new();
    public LockoutOptions Lockout { get; set; } = new();
    public TokenOptions Token { get; set; } = new();
    public AuditOptions Audit { get; set; } = new();
}

public class PasswordPolicyOptions
{
    public int MinLength { get; set; } = 8;
    public int MaxLength { get; set; } = 128;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireDigit { get; set; } = true;
    public bool RequireSpecialChar { get; set; } = true;
    public int PasswordHistoryCount { get; set; } = 5;
    public TimeSpan MinPasswordAge { get; set; } = TimeSpan.FromDays(1);
    public TimeSpan MaxPasswordAge { get; set; } = TimeSpan.FromDays(90);
}

public class SessionOptions
{
    public TimeSpan DefaultTimeout { get; set; } = TimeSpan.FromMinutes(30);
    public TimeSpan MaxTimeout { get; set; } = TimeSpan.FromHours(8);
    public bool RequireSecureCookie { get; set; } = true;
    public bool RequireHttpsOnly { get; set; } = true;
    public int MaxConcurrentSessions { get; set; } = 3;
    public bool SingleSignOnOnly { get; set; } = false;
}

public class LockoutOptions
{
    public bool EnableLockout { get; set; } = true;
    public int MaxFailedAttempts { get; set; } = 5;
    public TimeSpan DefaultLockoutDuration { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan MaxLockoutDuration { get; set; } = TimeSpan.FromHours(24);
    public bool EnableProgressiveLockout { get; set; } = true;
    public TimeSpan FailedAttemptWindow { get; set; } = TimeSpan.FromMinutes(10);
}

public class TokenOptions
{
    public TimeSpan DefaultAccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan DefaultRefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan DefaultResetTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan DefaultConfirmationTokenLifetime { get; set; } = TimeSpan.FromDays(1);
    public int TokenLength { get; set; } = 32;
    public bool RequireSecureTokens { get; set; } = true;
}

public class AuditOptions
{
    public bool EnableAuditLogging { get; set; } = true;
    public bool LogSensitiveData { get; set; } = false;
    public TimeSpan RetentionPeriod { get; set; } = TimeSpan.FromDays(90);
    public List<string> AuditedEntities { get; set; } = new() { "User", "Role", "UserRole", "TokenGrant", "UserSession" };
    public List<string> ExcludedProperties { get; set; } = new() { "PasswordHash", "SecurityStamp", "TokenHash" };
}