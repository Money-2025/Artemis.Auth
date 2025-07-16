namespace Artemis.Auth.Application.Common.Exceptions;

/// <summary>
/// Exception thrown when a business rule is violated (400 Bad Request)
/// </summary>
public class BusinessRuleException : Exception
{
    public string? Code { get; }
    public string? RuleType { get; }
    public string? Details { get; }
    public Dictionary<string, object> Properties { get; }
    
    public BusinessRuleException(string message, string? code = null, string? ruleType = null, string? details = null) 
        : base(message)
    {
        Code = code;
        RuleType = ruleType;
        Details = details;
        Properties = new Dictionary<string, object>();
    }
    
    public BusinessRuleException(string message, Exception innerException, string? code = null, string? ruleType = null, string? details = null) 
        : base(message, innerException)
    {
        Code = code;
        RuleType = ruleType;
        Details = details;
        Properties = new Dictionary<string, object>();
    }
    
    public BusinessRuleException(string message, string? code, string? ruleType, string? details, Dictionary<string, object> properties) 
        : base(message)
    {
        Code = code;
        RuleType = ruleType;
        Details = details;
        Properties = properties;
    }
    
    public static BusinessRuleException PasswordPolicy(string reason)
    {
        return new BusinessRuleException(
            "Password does not meet security requirements", 
            "PASSWORD_POLICY_VIOLATION",
            "PasswordPolicy",
            reason,
            new Dictionary<string, object> { { "reason", reason } });
    }
    
    public static BusinessRuleException PasswordRecentlyUsed(int historyCount)
    {
        return new BusinessRuleException(
            $"Password has been used in the last {historyCount} passwords", 
            "PASSWORD_RECENTLY_USED",
            "PasswordPolicy",
            $"Cannot reuse any of the last {historyCount} passwords",
            new Dictionary<string, object> { { "historyCount", historyCount } });
    }
    
    public static BusinessRuleException PasswordTooYoung(TimeSpan minAge)
    {
        return new BusinessRuleException(
            $"Password is too young to be changed (minimum age: {minAge.TotalHours} hours)", 
            "PASSWORD_TOO_YOUNG",
            "PasswordPolicy",
            $"Password can only be changed after {minAge.TotalHours} hours",
            new Dictionary<string, object> { { "minAgeHours", minAge.TotalHours } });
    }
    
    public static BusinessRuleException MaxSessionsReached(int maxSessions)
    {
        return new BusinessRuleException(
            $"Maximum number of concurrent sessions ({maxSessions}) has been reached", 
            "MAX_SESSIONS_REACHED",
            "SessionPolicy",
            $"User can have at most {maxSessions} active sessions",
            new Dictionary<string, object> { { "maxSessions", maxSessions } });
    }
    
    public static BusinessRuleException AccountLockout(int failedAttempts, int maxAttempts)
    {
        return new BusinessRuleException(
            $"Account locked due to {failedAttempts} failed login attempts", 
            "ACCOUNT_LOCKOUT",
            "SecurityPolicy",
            $"Account locked after {maxAttempts} failed attempts",
            new Dictionary<string, object> 
            { 
                { "failedAttempts", failedAttempts },
                { "maxAttempts", maxAttempts }
            });
    }
    
    public static BusinessRuleException CannotDeleteLastAdmin()
    {
        return new BusinessRuleException(
            "Cannot delete the last administrator account", 
            "CANNOT_DELETE_LAST_ADMIN",
            "SecurityPolicy",
            "At least one administrator account must remain active");
    }
    
    public static BusinessRuleException CannotDeleteSystemRole(string roleName)
    {
        return new BusinessRuleException(
            $"Cannot delete system role '{roleName}'", 
            "CANNOT_DELETE_SYSTEM_ROLE",
            "SecurityPolicy",
            $"System roles like '{roleName}' cannot be deleted",
            new Dictionary<string, object> { { "roleName", roleName } });
    }
    
    public static BusinessRuleException InvalidOperation(string operation, string reason)
    {
        return new BusinessRuleException(
            $"Invalid operation: {operation}", 
            "INVALID_OPERATION",
            "OperationPolicy",
            reason,
            new Dictionary<string, object> 
            { 
                { "operation", operation },
                { "reason", reason }
            });
    }
    
    public static BusinessRuleException MfaRequired()
    {
        return new BusinessRuleException(
            "Multi-factor authentication is required for this account", 
            "MFA_REQUIRED",
            "SecurityPolicy",
            "Account security policy requires MFA to be enabled");
    }
    
    public static BusinessRuleException EmailVerificationRequired()
    {
        return new BusinessRuleException(
            "Email verification is required", 
            "EMAIL_VERIFICATION_REQUIRED",
            "SecurityPolicy",
            "Email must be verified before performing this action");
    }
    
    public static BusinessRuleException PhoneVerificationRequired()
    {
        return new BusinessRuleException(
            "Phone verification is required", 
            "PHONE_VERIFICATION_REQUIRED",
            "SecurityPolicy",
            "Phone number must be verified before performing this action");
    }
    
    public static BusinessRuleException WeakPassword(string requirements)
    {
        return new BusinessRuleException(
            "Password does not meet strength requirements", 
            "WEAK_PASSWORD",
            "PasswordPolicy",
            requirements,
            new Dictionary<string, object> { { "requirements", requirements } });
    }
    
    public static BusinessRuleException DuplicateLoginAttempt(TimeSpan cooldown)
    {
        return new BusinessRuleException(
            $"Please wait {cooldown.TotalSeconds} seconds before attempting to login again", 
            "DUPLICATE_LOGIN_ATTEMPT",
            "SecurityPolicy",
            $"Login attempts must be spaced {cooldown.TotalSeconds} seconds apart",
            new Dictionary<string, object> { { "cooldownSeconds", cooldown.TotalSeconds } });
    }
    
    public static BusinessRuleException TokenExpired(string tokenType, DateTime expiredAt)
    {
        return new BusinessRuleException(
            $"{tokenType} token has expired", 
            "TOKEN_EXPIRED",
            "SecurityPolicy",
            $"Token expired at {expiredAt:yyyy-MM-dd HH:mm:ss} UTC",
            new Dictionary<string, object> 
            { 
                { "tokenType", tokenType },
                { "expiredAt", expiredAt }
            });
    }
    
    public static BusinessRuleException RateLimitExceeded(string operation, int limit, TimeSpan window)
    {
        return new BusinessRuleException(
            $"Rate limit exceeded for {operation}", 
            "RATE_LIMIT_EXCEEDED",
            "RateLimit",
            $"Maximum {limit} requests per {window.TotalMinutes} minutes",
            new Dictionary<string, object> 
            { 
                { "operation", operation },
                { "limit", limit },
                { "windowMinutes", window.TotalMinutes }
            });
    }
    
    public static BusinessRuleException InvalidTimeWindow(string operation, TimeSpan allowedWindow)
    {
        return new BusinessRuleException(
            $"Operation '{operation}' is not allowed at this time", 
            "INVALID_TIME_WINDOW",
            "TimePolicy",
            $"Operation only allowed within {allowedWindow.TotalHours} hours",
            new Dictionary<string, object> 
            { 
                { "operation", operation },
                { "allowedWindowHours", allowedWindow.TotalHours }
            });
    }
    
    public static BusinessRuleException GeolocationRestricted(string country)
    {
        return new BusinessRuleException(
            $"Access from {country} is restricted", 
            "GEOLOCATION_RESTRICTED",
            "SecurityPolicy",
            $"Access is not allowed from {country}",
            new Dictionary<string, object> { { "country", country } });
    }
}