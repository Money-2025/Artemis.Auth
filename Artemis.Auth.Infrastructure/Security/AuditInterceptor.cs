using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;
using Artemis.Auth.Domain.Common;
using System.Security.Claims;

namespace Artemis.Auth.Infrastructure.Security;

public class AuditInterceptor : SaveChangesInterceptor
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AuditInterceptor> _logger;
    
    public AuditInterceptor(IServiceProvider serviceProvider, ILogger<AuditInterceptor> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }
    
    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        if (eventData.Context == null)
            return await base.SavingChangesAsync(eventData, result, cancellationToken);
        
        var currentUserId = GetCurrentUserId();
        var auditEntries = new List<AuditEntry>();
        
        foreach (var entry in eventData.Context.ChangeTracker.Entries())
        {
            if (entry.Entity is AuditableEntity auditableEntity)
            {
                switch (entry.State)
                {
                    case EntityState.Added:
                        auditableEntity.CreatedAt = DateTime.UtcNow;
                        auditableEntity.CreatedBy = currentUserId;
                        auditEntries.Add(CreateAuditEntry(entry, AuditAction.Insert, currentUserId));
                        break;
                        
                    case EntityState.Modified:
                        auditableEntity.ModifiedAt = DateTime.UtcNow;
                        auditableEntity.ModifiedBy = currentUserId;
                        auditEntries.Add(CreateAuditEntry(entry, AuditAction.Update, currentUserId));
                        break;
                        
                    case EntityState.Deleted:
                        if (auditableEntity is ISoftDeletable softDeletable)
                        {
                            entry.State = EntityState.Modified;
                            softDeletable.IsDeleted = true;
                            softDeletable.DeletedAt = DateTime.UtcNow;
                            softDeletable.DeletedBy = currentUserId;
                            auditEntries.Add(CreateAuditEntry(entry, AuditAction.Delete, currentUserId));
                        }
                        break;
                }
            }
        }
        
        var saveResult = await base.SavingChangesAsync(eventData, result, cancellationToken);
        
        // Log audit entries after successful save
        if (auditEntries.Any())
        {
            await LogAuditEntriesAsync(eventData.Context, auditEntries, cancellationToken);
        }
        
        return saveResult;
    }
    
    private Guid? GetCurrentUserId()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var httpContextAccessor = scope.ServiceProvider.GetService<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
            
            if (httpContextAccessor?.HttpContext?.User?.Identity?.IsAuthenticated == true)
            {
                var userIdClaim = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier);
                if (userIdClaim != null && Guid.TryParse(userIdClaim.Value as string, out var userId))
                {
                    return userId;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get current user ID for audit logging");
        }
        
        return null;
    }
    
    private AuditEntry CreateAuditEntry(Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry entry, AuditAction action, Guid? userId)
    {
        var entityType = entry.Entity.GetType();
        var entityId = entry.Property("Id").CurrentValue as Guid?;
        
        return new AuditEntry
        {
            EntityType = entityType.Name,
            EntityId = entityId,
            Action = action,
            UserId = userId,
            Timestamp = DateTime.UtcNow,
            Changes = GetChanges(entry)
        };
    }
    
    private Dictionary<string, object?> GetChanges(Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry entry)
    {
        var changes = new Dictionary<string, object?>();
        
        foreach (var property in entry.Properties)
        {
            if (property.IsModified)
            {
                changes[property.Metadata.Name] = new
                {
                    OldValue = property.OriginalValue,
                    NewValue = property.CurrentValue
                };
            }
        }
        
        return changes;
    }
    
    private async Task LogAuditEntriesAsync(DbContext context, List<AuditEntry> auditEntries, CancellationToken cancellationToken)
    {
        try
        {
            foreach (var auditEntry in auditEntries)
            {
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    TableName = auditEntry.EntityType,
                    RecordId = auditEntry.EntityId.GetValueOrDefault(),
                    Action = auditEntry.Action,
                    PerformedBy = auditEntry.UserId,
                    PerformedAt = auditEntry.Timestamp,
                    NewData = System.Text.Json.JsonSerializer.Serialize(auditEntry.Changes),
                    IpAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent()
                };
                
                context.Set<AuditLog>().Add(auditLog);
            }
            
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log audit entries");
        }
    }
    
    private string? GetClientIpAddress()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var httpContextAccessor = scope.ServiceProvider.GetService<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
            return httpContextAccessor?.HttpContext?.Connection?.RemoteIpAddress?.ToString();
        }
        catch
        {
            return null;
        }
    }
    
    private string? GetUserAgent()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var httpContextAccessor = scope.ServiceProvider.GetService<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
            return httpContextAccessor?.HttpContext?.Request?.Headers["User-Agent"];
        }
        catch
        {
            return null;
        }
    }
}

public class AuditEntry
{
    public string EntityType { get; set; } = string.Empty;
    public Guid? EntityId { get; set; }
    public AuditAction Action { get; set; }
    public Guid? UserId { get; set; }
    public DateTime Timestamp { get; set; }
    public Dictionary<string, object?> Changes { get; set; } = new();
}