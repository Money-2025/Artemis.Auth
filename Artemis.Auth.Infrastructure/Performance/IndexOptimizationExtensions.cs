using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Performance;

public static class IndexOptimizationExtensions
{
    public static void AddOptimizedIndexes<TEntity>(this EntityTypeBuilder<TEntity> builder, DatabaseProvider databaseProvider)
        where TEntity : class
    {
        var entityName = typeof(TEntity).Name;
        
        // Add database-specific index optimizations
        switch (databaseProvider)
        {
            case DatabaseProvider.PostgreSQL:
                AddPostgreSQLOptimizations(builder, entityName);
                break;
            case DatabaseProvider.SqlServer:
                AddSqlServerOptimizations(builder, entityName);
                break;
            case DatabaseProvider.MySQL:
                AddMySQLOptimizations(builder, entityName);
                break;
        }
    }
    
    private static void AddPostgreSQLOptimizations<TEntity>(EntityTypeBuilder<TEntity> builder, string entityName)
        where TEntity : class
    {
        // PostgreSQL-specific optimizations
        if (typeof(TEntity).Name == "User")
        {
            // Partial index for active users only
            builder.HasIndex("NormalizedUsername")
                .HasDatabaseName($"IX_{entityName}_NormalizedUsername_Active")
                .HasFilter("\"is_deleted\" = false")
                .HasMethod("btree");
                
            // GIN index for full-text search on email
            builder.HasIndex("NormalizedEmail")
                .HasDatabaseName($"IX_{entityName}_NormalizedEmail_GIN")
                .HasMethod("gin");
        }
        else if (typeof(TEntity).Name == "AuditLog")
        {
            // BRIN index for time-series data
            builder.HasIndex("PerformedAt")
                .HasDatabaseName($"IX_{entityName}_PerformedAt_BRIN")
                .HasMethod("brin");
        }
    }
    
    private static void AddSqlServerOptimizations<TEntity>(EntityTypeBuilder<TEntity> builder, string entityName)
        where TEntity : class
    {
        // SQL Server-specific optimizations
        if (typeof(TEntity).Name == "User")
        {
            // Filtered index for active users
            builder.HasIndex("NormalizedUsername")
                .HasDatabaseName($"IX_{entityName}_NormalizedUsername_Active")
                .HasFilter("[is_deleted] = 0")
                .IncludeProperties("Email", "PhoneNumber");
        }
    }
    
    private static void AddMySQLOptimizations<TEntity>(EntityTypeBuilder<TEntity> builder, string entityName)
        where TEntity : class
    {
        // MySQL-specific optimizations
        if (typeof(TEntity).Name == "User")
        {
            // Prefix index for long strings
            builder.HasIndex("NormalizedUsername")
                .HasDatabaseName($"IX_{entityName}_NormalizedUsername_Prefix");
        }
    }
    
    public static void AddCompositeIndexes<TEntity>(this EntityTypeBuilder<TEntity> builder, DatabaseProvider databaseProvider)
        where TEntity : class
    {
        var entityName = typeof(TEntity).Name;
        
        // Add composite indexes based on common query patterns
        switch (entityName)
        {
            case "User":
                // Composite index for authentication queries
                builder.HasIndex("NormalizedUsername", "IsDeleted", "LockoutEnd")
                    .HasDatabaseName($"IX_{entityName}_Auth_Composite")
                    .HasFilter(databaseProvider.GetBooleanFilterSql("is_deleted", false));
                break;
                
            case "UserSession":
                // Composite index for session cleanup
                builder.HasIndex("UserId", "IsRevoked", "ExpiresAt")
                    .HasDatabaseName($"IX_{entityName}_Cleanup_Composite");
                break;
                
            case "TokenGrant":
                // Composite index for token validation
                builder.HasIndex("UserId", "TokenType", "IsUsed", "ExpiresAt")
                    .HasDatabaseName($"IX_{entityName}_Validation_Composite");
                break;
                
            case "AuditLog":
                // Composite index for audit queries
                builder.HasIndex("EntityType", "EntityId", "PerformedAt")
                    .HasDatabaseName($"IX_{entityName}_Entity_Audit_Composite");
                break;
        }
    }
    
    public static void AddCoveringIndexes<TEntity>(this EntityTypeBuilder<TEntity> builder, DatabaseProvider databaseProvider)
        where TEntity : class
    {
        var entityName = typeof(TEntity).Name;
        
        // Add covering indexes for common SELECT queries
        if (databaseProvider == DatabaseProvider.SqlServer)
        {
            switch (entityName)
            {
                case "User":
                    // Covering index for user lookup
                    builder.HasIndex("NormalizedUsername")
                        .HasDatabaseName($"IX_{entityName}_Lookup_Covering")
                        .IncludeProperties("Id", "Email", "EmailConfirmed", "PhoneNumber", "TwoFactorEnabled");
                    break;
                    
                case "UserRole":
                    // Covering index for role authorization
                    builder.HasIndex("UserId")
                        .HasDatabaseName($"IX_{entityName}_Authorization_Covering")
                        .IncludeProperties("RoleId", "IsDeleted", "AssignedAt");
                    break;
            }
        }
    }
}