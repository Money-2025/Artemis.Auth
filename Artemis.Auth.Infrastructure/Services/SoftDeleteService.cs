using Microsoft.EntityFrameworkCore;
using Artemis.Auth.Domain.Common;
using Artemis.Auth.Infrastructure.Persistence;

namespace Artemis.Auth.Infrastructure.Services;

public class SoftDeleteService
{
    private readonly AuthDbContext _context;
    
    public SoftDeleteService(AuthDbContext context)
    {
        _context = context;
    }
    
    public async Task<bool> SoftDeleteAsync<TEntity>(Guid id, Guid? deletedBy = null, CancellationToken cancellationToken = default)
        where TEntity : class, ISoftDeletable
    {
        var entity = await _context.Set<TEntity>().FindAsync(new object[] { id }, cancellationToken);
        
        if (entity == null || entity.IsDeleted)
        {
            return false;
        }
        
        entity.IsDeleted = true;
        entity.DeletedAt = DateTime.UtcNow;
        entity.DeletedBy = deletedBy;
        
        await _context.SaveChangesAsync(cancellationToken);
        return true;
    }
    
    public async Task<bool> RestoreAsync<TEntity>(Guid id, CancellationToken cancellationToken = default)
        where TEntity : class, ISoftDeletable
    {
        var entity = await _context.Set<TEntity>()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(e => e.GetType().GetProperty("Id")!.GetValue(e)!.Equals(id), cancellationToken);
        
        if (entity == null || !entity.IsDeleted)
        {
            return false;
        }
        
        entity.IsDeleted = false;
        entity.DeletedAt = null;
        entity.DeletedBy = null;
        
        await _context.SaveChangesAsync(cancellationToken);
        return true;
    }
    
    public async Task<bool> HardDeleteAsync<TEntity>(Guid id, CancellationToken cancellationToken = default)
        where TEntity : class, ISoftDeletable
    {
        var entity = await _context.Set<TEntity>()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(e => e.GetType().GetProperty("Id")!.GetValue(e)!.Equals(id), cancellationToken);
        
        if (entity == null)
        {
            return false;
        }
        
        _context.Set<TEntity>().Remove(entity);
        await _context.SaveChangesAsync(cancellationToken);
        return true;
    }
    
    public IQueryable<TEntity> GetDeletedEntities<TEntity>()
        where TEntity : class, ISoftDeletable
    {
        return _context.Set<TEntity>()
            .IgnoreQueryFilters()
            .Where(e => e.IsDeleted);
    }
    
    public async Task<int> PurgeDeletedAsync<TEntity>(TimeSpan olderThan, CancellationToken cancellationToken = default)
        where TEntity : class, ISoftDeletable
    {
        var cutoffDate = DateTime.UtcNow - olderThan;
        
        var entitiesToPurge = await _context.Set<TEntity>()
            .IgnoreQueryFilters()
            .Where(e => e.IsDeleted && e.DeletedAt < cutoffDate)
            .ToListAsync(cancellationToken);
        
        if (entitiesToPurge.Any())
        {
            _context.Set<TEntity>().RemoveRange(entitiesToPurge);
            await _context.SaveChangesAsync(cancellationToken);
        }
        
        return entitiesToPurge.Count;
    }
}