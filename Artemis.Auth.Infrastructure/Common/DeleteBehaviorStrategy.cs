using Microsoft.EntityFrameworkCore;

namespace Artemis.Auth.Infrastructure.Common;

/// <summary>
/// Defines delete behavior strategies for different entity relationships
/// </summary>
public static class DeleteBehaviorStrategy
{
    /// <summary>
    /// For critical security entities - archive instead of delete
    /// </summary>
    public static DeleteBehavior Archive => DeleteBehavior.Restrict;
    
    /// <summary>
    /// For user-owned data - soft delete cascade
    /// </summary>
    public static DeleteBehavior UserOwned => DeleteBehavior.Cascade;
    
    /// <summary>
    /// For session data - hard delete cascade (can be recreated)
    /// </summary>
    public static DeleteBehavior SessionData => DeleteBehavior.Cascade;
    
    /// <summary>
    /// For audit/history data - preserve with null reference
    /// </summary>
    public static DeleteBehavior AuditData => DeleteBehavior.SetNull;
    
    /// <summary>
    /// For reference data - restrict deletion
    /// </summary>
    public static DeleteBehavior ReferenceData => DeleteBehavior.Restrict;
    
    /// <summary>
    /// For junction tables - clean cascade
    /// </summary>
    public static DeleteBehavior Junction => DeleteBehavior.Cascade;
    
    /// <summary>
    /// For security-sensitive data - requires manual cleanup
    /// </summary>
    public static DeleteBehavior SecuritySensitive => DeleteBehavior.Restrict;
}