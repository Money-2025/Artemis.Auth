namespace Artemis.Auth.Application.Common.Exceptions;

/// <summary>
/// Exception thrown when a user is not authorized to perform an action (401 Unauthorized)
/// </summary>
public class UnauthorizedException : Exception
{
    public string? Code { get; }
    public Dictionary<string, object> Properties { get; }
    
    public UnauthorizedException(string message, string? code = null) 
        : base(message)
    {
        Code = code;
        Properties = new Dictionary<string, object>();
    }
    
    public UnauthorizedException(string message, Exception innerException, string? code = null) 
        : base(message, innerException)
    {
        Code = code;
        Properties = new Dictionary<string, object>();
    }
    
    public UnauthorizedException(string message, string? code, Dictionary<string, object> properties) 
        : base(message)
    {
        Code = code;
        Properties = properties;
    }
    
    public static UnauthorizedException InvalidToken(string? tokenType = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(tokenType))
            props["tokenType"] = tokenType;
            
        return new UnauthorizedException(
            "Invalid or expired token", 
            "INVALID_TOKEN", 
            props);
    }
    
    public static UnauthorizedException TokenExpired(string? tokenType = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(tokenType))
            props["tokenType"] = tokenType;
            
        return new UnauthorizedException(
            "Token has expired", 
            "TOKEN_EXPIRED", 
            props);
    }
    
    public static UnauthorizedException SessionExpired()
    {
        return new UnauthorizedException(
            "Session has expired", 
            "SESSION_EXPIRED");
    }
    
    public static UnauthorizedException InvalidCredentials(string? username = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(username))
            props["username"] = username;
            
        return new UnauthorizedException(
            "Invalid username or password", 
            "INVALID_CREDENTIALS", 
            props);
    }
    
    public static UnauthorizedException AccountLocked(DateTime? lockoutEnd = null)
    {
        var props = new Dictionary<string, object>();
        if (lockoutEnd.HasValue)
            props["lockoutEnd"] = lockoutEnd.Value;
            
        return new UnauthorizedException(
            "Account is locked", 
            "ACCOUNT_LOCKED", 
            props);
    }
    
    public static UnauthorizedException AccountNotConfirmed()
    {
        return new UnauthorizedException(
            "Account email is not confirmed", 
            "ACCOUNT_NOT_CONFIRMED");
    }
    
    public static UnauthorizedException TwoFactorRequired()
    {
        return new UnauthorizedException(
            "Two-factor authentication is required", 
            "TWO_FACTOR_REQUIRED");
    }
    
    public static UnauthorizedException InvalidMfaCode()
    {
        return new UnauthorizedException(
            "Invalid two-factor authentication code", 
            "INVALID_MFA_CODE");
    }
    
    public static UnauthorizedException AuthenticationRequired()
    {
        return new UnauthorizedException(
            "Authentication is required to access this resource", 
            "AUTHENTICATION_REQUIRED");
    }
    
    public static UnauthorizedException InvalidRefreshToken()
    {
        return new UnauthorizedException(
            "Invalid or expired refresh token", 
            "INVALID_REFRESH_TOKEN");
    }
    
    public static UnauthorizedException AccountDisabled()
    {
        return new UnauthorizedException(
            "Account is disabled", 
            "ACCOUNT_DISABLED");
    }
    
    public static UnauthorizedException InvalidPasswordResetToken()
    {
        return new UnauthorizedException(
            "Invalid or expired password reset token", 
            "INVALID_PASSWORD_RESET_TOKEN");
    }
}