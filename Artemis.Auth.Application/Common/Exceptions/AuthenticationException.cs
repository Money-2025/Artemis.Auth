namespace Artemis.Auth.Application.Common.Exceptions;

public class AuthenticationException : Exception
{
    public string? Code { get; }
    public Dictionary<string, object> Properties { get; }
    
    public AuthenticationException(string message, string? code = null) 
        : base(message)
    {
        Code = code;
        Properties = new Dictionary<string, object>();
    }
    
    public AuthenticationException(string message, Exception innerException, string? code = null) 
        : base(message, innerException)
    {
        Code = code;
        Properties = new Dictionary<string, object>();
    }
    
    public AuthenticationException(string message, string? code, Dictionary<string, object> properties) 
        : base(message)
    {
        Code = code;
        Properties = properties;
    }
    
    public static AuthenticationException InvalidCredentials(string? username = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(username))
            props["username"] = username;
            
        return new AuthenticationException(
            "Invalid username or password", 
            "INVALID_CREDENTIALS", 
            props);
    }
    
    public static AuthenticationException AccountLocked(DateTime? lockoutEnd = null)
    {
        var props = new Dictionary<string, object>();
        if (lockoutEnd.HasValue)
            props["lockoutEnd"] = lockoutEnd.Value;
            
        return new AuthenticationException(
            "Account is locked", 
            "ACCOUNT_LOCKED", 
            props);
    }
    
    public static AuthenticationException AccountNotConfirmed()
    {
        return new AuthenticationException(
            "Account email is not confirmed", 
            "ACCOUNT_NOT_CONFIRMED");
    }
    
    public static AuthenticationException TwoFactorRequired()
    {
        return new AuthenticationException(
            "Two-factor authentication is required", 
            "TWO_FACTOR_REQUIRED");
    }
    
    public static AuthenticationException InvalidToken(string? tokenType = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(tokenType))
            props["tokenType"] = tokenType;
            
        return new AuthenticationException(
            "Invalid or expired token", 
            "INVALID_TOKEN", 
            props);
    }
    
    public static AuthenticationException TokenExpired(string? tokenType = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(tokenType))
            props["tokenType"] = tokenType;
            
        return new AuthenticationException(
            "Token has expired", 
            "TOKEN_EXPIRED", 
            props);
    }
    
    public static AuthenticationException SessionExpired()
    {
        return new AuthenticationException(
            "Session has expired", 
            "SESSION_EXPIRED");
    }
    
    public static AuthenticationException InsufficientPermissions(string? permission = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(permission))
            props["permission"] = permission;
            
        return new AuthenticationException(
            "Insufficient permissions", 
            "INSUFFICIENT_PERMISSIONS", 
            props);
    }
}