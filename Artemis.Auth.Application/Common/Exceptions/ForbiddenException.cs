namespace Artemis.Auth.Application.Common.Exceptions;

/// <summary>
/// Exception thrown when a user is authenticated but does not have permission to perform an action (403 Forbidden)
/// </summary>
public class ForbiddenException : Exception
{
    public string? Code { get; }
    public string? RequiredPermission { get; }
    public Dictionary<string, object> Properties { get; }
    
    public ForbiddenException(string message, string? code = null, string? requiredPermission = null) 
        : base(message)
    {
        Code = code;
        RequiredPermission = requiredPermission;
        Properties = new Dictionary<string, object>();
    }
    
    public ForbiddenException(string message, Exception innerException, string? code = null, string? requiredPermission = null) 
        : base(message, innerException)
    {
        Code = code;
        RequiredPermission = requiredPermission;
        Properties = new Dictionary<string, object>();
    }
    
    public ForbiddenException(string message, string? code, string? requiredPermission, Dictionary<string, object> properties) 
        : base(message)
    {
        Code = code;
        RequiredPermission = requiredPermission;
        Properties = properties;
    }
    
    public static ForbiddenException InsufficientPermissions(string? permission = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(permission))
            props["permission"] = permission;
            
        return new ForbiddenException(
            "You don't have sufficient permissions to perform this action", 
            "INSUFFICIENT_PERMISSIONS", 
            permission,
            props);
    }
    
    public static ForbiddenException RequiredRole(string roleName)
    {
        return new ForbiddenException(
            $"This action requires the '{roleName}' role", 
            "REQUIRED_ROLE",
            roleName,
            new Dictionary<string, object> { { "requiredRole", roleName } });
    }
    
    public static ForbiddenException RequiredRoles(params string[] roleNames)
    {
        var rolesStr = string.Join(", ", roleNames);
        return new ForbiddenException(
            $"This action requires one of the following roles: {rolesStr}", 
            "REQUIRED_ROLES",
            rolesStr,
            new Dictionary<string, object> { { "requiredRoles", roleNames } });
    }
    
    public static ForbiddenException AdminOnly()
    {
        return new ForbiddenException(
            "This action is restricted to administrators only", 
            "ADMIN_ONLY",
            "Admin");
    }
    
    public static ForbiddenException ResourceOwnerOnly()
    {
        return new ForbiddenException(
            "You can only access your own resources", 
            "RESOURCE_OWNER_ONLY");
    }
    
    public static ForbiddenException AccountSuspended()
    {
        return new ForbiddenException(
            "Your account has been suspended", 
            "ACCOUNT_SUSPENDED");
    }
    
    public static ForbiddenException FeatureDisabled(string feature)
    {
        return new ForbiddenException(
            $"The '{feature}' feature is disabled", 
            "FEATURE_DISABLED",
            feature,
            new Dictionary<string, object> { { "feature", feature } });
    }
    
    public static ForbiddenException MaintenanceMode()
    {
        return new ForbiddenException(
            "System is in maintenance mode", 
            "MAINTENANCE_MODE");
    }
    
    public static ForbiddenException IpAddressBlocked(string? ipAddress = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(ipAddress))
            props["ipAddress"] = ipAddress;
            
        return new ForbiddenException(
            "Your IP address has been blocked", 
            "IP_ADDRESS_BLOCKED",
            null,
            props);
    }
    
    public static ForbiddenException GeoLocationBlocked(string? country = null)
    {
        var props = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(country))
            props["country"] = country;
            
        return new ForbiddenException(
            "Access from your geographic location is not allowed", 
            "GEO_LOCATION_BLOCKED",
            null,
            props);
    }
    
    public static ForbiddenException TwoFactorRequired()
    {
        return new ForbiddenException(
            "Two-factor authentication is required for this action", 
            "TWO_FACTOR_REQUIRED");
    }
    
    public static ForbiddenException EmailNotVerified()
    {
        return new ForbiddenException(
            "Email verification is required to perform this action", 
            "EMAIL_NOT_VERIFIED");
    }
    
    public static ForbiddenException PhoneNotVerified()
    {
        return new ForbiddenException(
            "Phone verification is required to perform this action", 
            "PHONE_NOT_VERIFIED");
    }
    
    public static ForbiddenException PolicyViolation(string policy)
    {
        return new ForbiddenException(
            $"This action violates the '{policy}' policy", 
            "POLICY_VIOLATION",
            policy,
            new Dictionary<string, object> { { "policy", policy } });
    }
}