using Microsoft.EntityFrameworkCore;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Persistence;

namespace Artemis.Auth.Infrastructure.Persistence.Repositories;

/// <summary>
/// Base repository providing common CRUD operations for all entities that inherit from AuditableEntity
/// Implements generic repository pattern with EF Core optimizations
/// Uses your existing AuthDbContext with all interceptors and configurations
/// </summary>
/// <typeparam name="TEntity">Entity type that must inherit from AuditableEntity (has audit fields + soft delete)</typeparam>
public abstract class BaseRepository<TEntity> where TEntity : AuditableEntity
{
    protected readonly AuthDbContext _context;
    protected readonly DbSet<TEntity> _dbSet;

    /// <summary>
    /// Constructor: Injects your AuthDbContext and gets the DbSet for the entity
    /// Uses your existing context with all interceptors (Audit, Security, Performance)
    /// </summary>
    protected BaseRepository(AuthDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _dbSet = _context.Set<TEntity>();
    }

    /// <summary>
    /// Gets entity by ID with optional tracking
    /// Uses .AsNoTracking() for read-only operations (better performance)
    /// Automatically excludes soft-deleted entities via your query filters
    /// </summary>
    protected virtual async Task<TEntity?> GetByIdAsync(Guid id, bool trackChanges = false, CancellationToken cancellationToken = default)
    {
        var query = trackChanges ? _dbSet : _dbSet.AsNoTracking();
        return await query.FirstOrDefaultAsync(e => e.Id == id, cancellationToken);
    }

    /// <summary>
    /// Gets all entities with optional tracking and pagination
    /// Uses .AsNoTracking() for read-only scenarios
    /// Automatically excludes soft-deleted entities
    /// </summary>
    protected virtual async Task<IEnumerable<TEntity>> GetAllAsync(bool trackChanges = false, CancellationToken cancellationToken = default)
    {
        var query = trackChanges ? _dbSet : _dbSet.AsNoTracking();
        return await query.ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Generic method to find entities by a predicate
    /// Useful for custom queries like GetByUsername, GetByEmail
    /// Uses .AsNoTracking() for read-only operations
    /// </summary>
    protected virtual async Task<TEntity?> FindByConditionAsync(
        System.Linq.Expressions.Expression<Func<TEntity, bool>> expression,
        bool trackChanges = false,
        CancellationToken cancellationToken = default)
    {
        var query = trackChanges ? _dbSet : _dbSet.AsNoTracking();
        return await query.FirstOrDefaultAsync(expression, cancellationToken);
    }

    /// <summary>
    /// Generic method to find multiple entities by a predicate
    /// Useful for queries like GetUsersByRole, GetActiveUsers
    /// </summary>
    protected virtual async Task<IEnumerable<TEntity>> FindManyByConditionAsync(
        System.Linq.Expressions.Expression<Func<TEntity, bool>> expression,
        bool trackChanges = false,
        CancellationToken cancellationToken = default)
    {
        var query = trackChanges ? _dbSet : _dbSet.AsNoTracking();
        return await query.Where(expression).ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Creates a new entity
    /// Uses your AuditInterceptor to automatically set CreatedAt, CreatedBy
    /// Returns the created entity with generated ID
    /// </summary>
    protected virtual async Task<TEntity> CreateAsync(TEntity entity, CancellationToken cancellationToken = default)
    {
        if (entity == null)
            throw new ArgumentNullException(nameof(entity));

        // Your AuditInterceptor will automatically set CreatedAt, CreatedBy
        var result = await _dbSet.AddAsync(entity, cancellationToken);
        return result.Entity;
    }

    /// <summary>
    /// Updates an existing entity
    /// Uses your AuditInterceptor to automatically set ModifiedAt, ModifiedBy
    /// EF Core will track changes and update only modified fields
    /// </summary>
    protected virtual TEntity Update(TEntity entity)
    {
        if (entity == null)
            throw new ArgumentNullException(nameof(entity));

        // Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
        var result = _dbSet.Update(entity);
        return result.Entity;
    }

    /// <summary>
    /// Soft deletes an entity (sets IsDeleted = true)
    /// Uses your AuditInterceptor to automatically set DeletedAt, DeletedBy
    /// Entity will be excluded from queries via your query filters
    /// </summary>
    protected virtual void Delete(TEntity entity)
    {
        if (entity == null)
            throw new ArgumentNullException(nameof(entity));

        // Your AuditInterceptor will convert this to soft delete
        // and set IsDeleted = true, DeletedAt = now, DeletedBy = currentUser
        _dbSet.Remove(entity);
    }

    /// <summary>
    /// Hard deletes an entity (permanent removal)
    /// Use with caution - bypasses soft delete mechanism
    /// Only use for cleanup operations or when explicitly required
    /// </summary>
    protected virtual void HardDelete(TEntity entity)
    {
        if (entity == null)
            throw new ArgumentNullException(nameof(entity));

        // This will perform actual deletion, bypassing soft delete
        _context.Entry(entity).State = EntityState.Deleted;
    }

    /// <summary>
    /// Checks if an entity exists by ID
    /// Uses efficient .AnyAsync() instead of loading the entity
    /// Automatically excludes soft-deleted entities
    /// </summary>
    protected virtual async Task<bool> ExistsAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _dbSet.AnyAsync(e => e.Id == id, cancellationToken);
    }

    /// <summary>
    /// Checks if any entity matches the condition
    /// Uses efficient .AnyAsync() for existence checks
    /// </summary>
    protected virtual async Task<bool> AnyAsync(
        System.Linq.Expressions.Expression<Func<TEntity, bool>> expression,
        CancellationToken cancellationToken = default)
    {
        return await _dbSet.AnyAsync(expression, cancellationToken);
    }

    /// <summary>
    /// Counts entities matching the condition
    /// Uses efficient .CountAsync() without loading entities
    /// </summary>
    protected virtual async Task<int> CountAsync(
        System.Linq.Expressions.Expression<Func<TEntity, bool>>? expression = null,
        CancellationToken cancellationToken = default)
    {
        return expression == null
            ? await _dbSet.CountAsync(cancellationToken)
            : await _dbSet.CountAsync(expression, cancellationToken);
    }

    /// <summary>
    /// Gets a queryable for complex queries
    /// Allows repositories to build complex queries with joins, includes, etc.
    /// Use with caution - prefer specific methods for common operations
    /// </summary>
    protected virtual IQueryable<TEntity> GetQueryable(bool trackChanges = false)
    {
        return trackChanges ? _dbSet : _dbSet.AsNoTracking();
    }

    /// <summary>
    /// Saves changes to the database
    /// Uses your UnitOfWork pattern - this is here for internal use
    /// Prefer calling SaveChanges through UnitOfWork in your handlers
    /// </summary>
    protected virtual async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return await _context.SaveChangesAsync(cancellationToken);
    }
}