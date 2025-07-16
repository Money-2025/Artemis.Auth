namespace Artemis.Auth.Application.Common.Exceptions;

/// <summary>
/// Exception thrown when a request conflicts with the current state of the resource (409 Conflict)
/// </summary>
public class ConflictException : Exception
{
    public string? Code { get; }
    public string? ConflictType { get; }
    public Dictionary<string, object> Properties { get; }
    
    public ConflictException(string message, string? code = null, string? conflictType = null) 
        : base(message)
    {
        Code = code;
        ConflictType = conflictType;
        Properties = new Dictionary<string, object>();
    }
    
    public ConflictException(string message, Exception innerException, string? code = null, string? conflictType = null) 
        : base(message, innerException)
    {
        Code = code;
        ConflictType = conflictType;
        Properties = new Dictionary<string, object>();
    }
    
    public ConflictException(string message, string? code, string? conflictType, Dictionary<string, object> properties) 
        : base(message)
    {
        Code = code;
        ConflictType = conflictType;
        Properties = properties;
    }
    
    public static ConflictException DuplicateResource(string resourceType, string identifier)
    {
        return new ConflictException(
            $"{resourceType} with identifier '{identifier}' already exists", 
            "DUPLICATE_RESOURCE",
            "Duplicate",
            new Dictionary<string, object> 
            { 
                { "resourceType", resourceType }, 
                { "identifier", identifier } 
            });
    }
    
    public static ConflictException DuplicateUser(string identifier)
    {
        return new ConflictException(
            $"User with identifier '{identifier}' already exists", 
            "DUPLICATE_USER",
            "Duplicate",
            new Dictionary<string, object> { { "identifier", identifier } });
    }
    
    public static ConflictException DuplicateEmail(string email)
    {
        return new ConflictException(
            $"Email '{email}' is already registered", 
            "DUPLICATE_EMAIL",
            "Duplicate",
            new Dictionary<string, object> { { "email", email } });
    }
    
    public static ConflictException DuplicateUsername(string username)
    {
        return new ConflictException(
            $"Username '{username}' is already taken", 
            "DUPLICATE_USERNAME",
            "Duplicate",
            new Dictionary<string, object> { { "username", username } });
    }
    
    public static ConflictException DuplicatePhoneNumber(string phoneNumber)
    {
        return new ConflictException(
            $"Phone number '{phoneNumber}' is already registered", 
            "DUPLICATE_PHONE_NUMBER",
            "Duplicate",
            new Dictionary<string, object> { { "phoneNumber", phoneNumber } });
    }
    
    public static ConflictException DuplicateRole(string roleName)
    {
        return new ConflictException(
            $"Role '{roleName}' already exists", 
            "DUPLICATE_ROLE",
            "Duplicate",
            new Dictionary<string, object> { { "roleName", roleName } });
    }
    
    public static ConflictException ConcurrencyConflict(string entityType, object entityId)
    {
        return new ConflictException(
            $"Concurrency conflict occurred while updating {entityType} '{entityId}'", 
            "CONCURRENCY_CONFLICT",
            "Concurrency",
            new Dictionary<string, object> 
            { 
                { "entityType", entityType }, 
                { "entityId", entityId } 
            });
    }
    
    public static ConflictException ResourceInUse(string resourceType, string identifier)
    {
        return new ConflictException(
            $"{resourceType} '{identifier}' is currently in use and cannot be modified", 
            "RESOURCE_IN_USE",
            "InUse",
            new Dictionary<string, object> 
            { 
                { "resourceType", resourceType }, 
                { "identifier", identifier } 
            });
    }
    
    public static ConflictException RoleInUse(string roleName, int userCount)
    {
        return new ConflictException(
            $"Role '{roleName}' is assigned to {userCount} users and cannot be deleted", 
            "ROLE_IN_USE",
            "InUse",
            new Dictionary<string, object> 
            { 
                { "roleName", roleName }, 
                { "userCount", userCount } 
            });
    }
    
    public static ConflictException SessionConflict(string reason)
    {
        return new ConflictException(
            $"Session conflict: {reason}", 
            "SESSION_CONFLICT",
            "Session",
            new Dictionary<string, object> { { "reason", reason } });
    }
    
    public static ConflictException StateConflict(string currentState, string requestedState)
    {
        return new ConflictException(
            $"Cannot transition from '{currentState}' to '{requestedState}'", 
            "STATE_CONFLICT",
            "State",
            new Dictionary<string, object> 
            { 
                { "currentState", currentState }, 
                { "requestedState", requestedState } 
            });
    }
    
    public static ConflictException AlreadyExists(string resourceType, string identifier)
    {
        return new ConflictException(
            $"{resourceType} '{identifier}' already exists", 
            "ALREADY_EXISTS",
            "Duplicate",
            new Dictionary<string, object> 
            { 
                { "resourceType", resourceType }, 
                { "identifier", identifier } 
            });
    }
    
    public static ConflictException AlreadyProcessed(string operationType, string operationId)
    {
        return new ConflictException(
            $"Operation '{operationType}' with ID '{operationId}' has already been processed", 
            "ALREADY_PROCESSED",
            "Duplicate",
            new Dictionary<string, object> 
            { 
                { "operationType", operationType }, 
                { "operationId", operationId } 
            });
    }
    
    public static ConflictException VersionConflict(string entityType, object entityId, string expectedVersion, string actualVersion)
    {
        return new ConflictException(
            $"Version conflict for {entityType} '{entityId}'. Expected version '{expectedVersion}' but found '{actualVersion}'", 
            "VERSION_CONFLICT",
            "Version",
            new Dictionary<string, object> 
            { 
                { "entityType", entityType }, 
                { "entityId", entityId },
                { "expectedVersion", expectedVersion },
                { "actualVersion", actualVersion }
            });
    }
    
    public static ConflictException MaxLimitReached(string resourceType, int currentCount, int maxLimit)
    {
        return new ConflictException(
            $"Maximum limit of {maxLimit} {resourceType} has been reached (current: {currentCount})", 
            "MAX_LIMIT_REACHED",
            "Limit",
            new Dictionary<string, object> 
            { 
                { "resourceType", resourceType }, 
                { "currentCount", currentCount },
                { "maxLimit", maxLimit }
            });
    }
}