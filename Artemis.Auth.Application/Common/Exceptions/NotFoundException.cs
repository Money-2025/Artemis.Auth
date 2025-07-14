namespace Artemis.Auth.Application.Common.Exceptions;

public class NotFoundException : Exception
{
    public string? EntityName { get; }
    public object? EntityId { get; }
    
    public NotFoundException(string message) 
        : base(message)
    {
    }
    
    public NotFoundException(string entityName, object entityId) 
        : base($"{entityName} with id '{entityId}' was not found.")
    {
        EntityName = entityName;
        EntityId = entityId;
    }
    
    public NotFoundException(string entityName, object entityId, string message) 
        : base(message)
    {
        EntityName = entityName;
        EntityId = entityId;
    }
    
    public NotFoundException(string message, Exception innerException) 
        : base(message, innerException)
    {
    }
    
    public static NotFoundException ForUser(Guid userId)
    {
        return new NotFoundException("User", userId);
    }
    
    public static NotFoundException ForUser(string username)
    {
        return new NotFoundException("User", username, $"User with username '{username}' was not found.");
    }
    
    public static NotFoundException ForUserByEmail(string email)
    {
        return new NotFoundException("User", email, $"User with email '{email}' was not found.");
    }
    
    public static NotFoundException ForRole(Guid roleId)
    {
        return new NotFoundException("Role", roleId);
    }
    
    public static NotFoundException ForRole(string roleName)
    {
        return new NotFoundException("Role", roleName, $"Role with name '{roleName}' was not found.");
    }
    
    public static NotFoundException ForSession(Guid sessionId)
    {
        return new NotFoundException("Session", sessionId);
    }
    
    public static NotFoundException ForToken(string tokenType)
    {
        return new NotFoundException("Token", tokenType, $"Token of type '{tokenType}' was not found.");
    }
    
    public static NotFoundException ForEntity<T>(object id) where T : class
    {
        return new NotFoundException(typeof(T).Name, id);
    }
    
    public static NotFoundException ForEntity(string entityName, object id)
    {
        return new NotFoundException(entityName, id);
    }
}