namespace Artemis.Auth.Application.Common.Exceptions;

public class BusinessException : Exception
{
    public string? Code { get; }
    public Dictionary<string, object> Properties { get; }
    
    public BusinessException(string message, string? code = null) 
        : base(message)
    {
        Code = code;
        Properties = new Dictionary<string, object>();
    }
    
    public BusinessException(string message, Exception innerException, string? code = null) 
        : base(message, innerException)
    {
        Code = code;
        Properties = new Dictionary<string, object>();
    }
    
    public BusinessException(string message, string? code, Dictionary<string, object> properties) 
        : base(message)
    {
        Code = code;
        Properties = properties;
    }
    
    public static BusinessException DuplicateUser(string identifier)
    {
        return new BusinessException(
            $"User with identifier '{identifier}' already exists", 
            "DUPLICATE_USER",
            new Dictionary<string, object> { { "identifier", identifier } });
    }
    
    public static BusinessException DuplicateRole(string roleName)
    {
        return new BusinessException(
            $"Role '{roleName}' already exists", 
            "DUPLICATE_ROLE",
            new Dictionary<string, object> { { "roleName", roleName } });
    }
    
    public static BusinessException CannotDeleteSystemRole(string roleName)
    {
        return new BusinessException(
            $"Cannot delete system role '{roleName}'", 
            "CANNOT_DELETE_SYSTEM_ROLE",
            new Dictionary<string, object> { { "roleName", roleName } });
    }
    
    public static BusinessException CannotRemoveLastAdmin()
    {
        return new BusinessException(
            "Cannot remove the last administrator", 
            "CANNOT_REMOVE_LAST_ADMIN");
    }
    
    public static BusinessException PasswordRecentlyUsed()
    {
        return new BusinessException(
            "Password has been recently used and cannot be reused", 
            "PASSWORD_RECENTLY_USED");
    }
    
    public static BusinessException PasswordTooYoung()
    {
        return new BusinessException(
            "Password is too young to be changed", 
            "PASSWORD_TOO_YOUNG");
    }
    
    public static BusinessException MaxSessionsReached(int maxSessions)
    {
        return new BusinessException(
            $"Maximum number of sessions ({maxSessions}) has been reached", 
            "MAX_SESSIONS_REACHED",
            new Dictionary<string, object> { { "maxSessions", maxSessions } });
    }
    
    public static BusinessException InvalidOperation(string operation)
    {
        return new BusinessException(
            $"Invalid operation: {operation}", 
            "INVALID_OPERATION",
            new Dictionary<string, object> { { "operation", operation } });
    }
    
    public static BusinessException ResourceLocked(string resource)
    {
        return new BusinessException(
            $"Resource '{resource}' is currently locked", 
            "RESOURCE_LOCKED",
            new Dictionary<string, object> { { "resource", resource } });
    }
    
    public static BusinessException ConcurrencyConflict(string entity)
    {
        return new BusinessException(
            $"Concurrency conflict occurred while updating {entity}", 
            "CONCURRENCY_CONFLICT",
            new Dictionary<string, object> { { "entity", entity } });
    }
    
    public static BusinessException RoleInUse(string roleName, int userCount)
    {
        return new BusinessException(
            $"Role '{roleName}' is assigned to {userCount} users and cannot be deleted", 
            "ROLE_IN_USE",
            new Dictionary<string, object> { { "roleName", roleName }, { "userCount", userCount } });
    }
}