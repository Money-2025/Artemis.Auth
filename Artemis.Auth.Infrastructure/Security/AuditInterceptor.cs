using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;
using Artemis.Auth.Domain.Common;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Artemis.Auth.Infrastructure.Security;

public class AuditInterceptor : SaveChangesInterceptor
{
    private readonly IHttpContextAccessor _http;
    private readonly ILogger<AuditInterceptor> _logger;

    public AuditInterceptor(IHttpContextAccessor http, ILogger<AuditInterceptor> logger)
    {
        _http = http;
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
        
        // Tek (asıl) SaveChanges çağrısı – ikinci bir Save yok.
        var saveResult = await base.SavingChangesAsync(eventData, result, cancellationToken);

        // Burada auditEntries'i şu an sadece bellekte tutuyorsun (persist etmiyorsun).
        // İleride tekrar aktif etmek istersen auditleri aynı transaction'da yazmak için
        // burada ikinci Save çağrısı yapmadan context'e AddRange edip base'e gitmen gerekir.
        // Şimdilik sonsuz döngü problemini çözmek adına hiçbir ek işlem yok.
        
        return saveResult;
    }
    
    private Guid? GetCurrentUserId()
    {
        try
        {
            var user = _http.HttpContext?.User;
            if (user?.Identity?.IsAuthenticated == true)
            {
                var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier);
                if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
                    return userId;
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

    // Şu an kullanılmıyor; audit logları DB'ye yazılmadığı için tutuldu.
    // Eğer tekrar kullanmak istersen IHttpContextAccessor zaten elimizde.
    private string? GetClientIpAddress()
        => _http.HttpContext?.Connection?.RemoteIpAddress?.ToString();
    
    private string? GetUserAgent()
        => _http.HttpContext?.Request?.Headers["User-Agent"].ToString();
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
