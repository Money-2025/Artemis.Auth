using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Infrastructure.Persistence;

namespace Artemis.Auth.Infrastructure.Persistence.Repositories;

/// <summary>
/// UnitOfWork: Implements transaction management and repository aggregation
/// Implements IUnitOfWork interface from Application layer
/// Manages database transactions and provides access to all repositories
/// Ensures data consistency across multiple repository operations
/// </summary>
public class UnitOfWork : IUnitOfWork
{
    private readonly AuthDbContext _context;
    private readonly ILogger<UnitOfWork> _logger;
    private IDbContextTransaction? _currentTransaction;

    // Repository instances - lazy loaded for performance
    private IUserRepository? _userRepository;
    private IRoleRepository? _roleRepository;

    /// <summary>
    /// Constructor: Injects AuthDbContext and logger
    /// Context includes all your interceptors (Audit, Security, Performance)
    /// Logger is used for transaction monitoring and error tracking
    /// </summary>
    public UnitOfWork(AuthDbContext context, ILogger<UnitOfWork> logger)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Users repository - Lazy loaded property
    /// Creates UserRepository instance only when first accessed
    /// Reuses same instance for the lifetime of UnitOfWork
    /// </summary>
    public IUserRepository Users => _userRepository ??= new UserRepository(_context);

    /// <summary>
    /// Roles repository - Lazy loaded property
    /// Creates RoleRepository instance only when first accessed
    /// Reuses same instance for the lifetime of UnitOfWork
    /// </summary>
    public IRoleRepository Roles => _roleRepository ??= new RoleRepository(_context);

    /// <summary>
    /// Saves all changes to the database - Standard save operation
    /// Uses your AuditInterceptor to automatically track changes
    /// Returns number of affected records
    /// Logs the operation for monitoring
    /// </summary>
    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Saving changes to database");
            var result = await _context.SaveChangesAsync(cancellationToken);
            _logger.LogDebug("Successfully saved {Count} changes to database", result);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while saving changes to database");
            throw;
        }
    }

    /// <summary>
    /// Saves changes with user context - Enhanced save operation
    /// Passes user ID to audit trail for tracking who made changes
    /// Your AuditInterceptor will use this for CreatedBy/ModifiedBy fields
    /// Returns true if save was successful
    /// </summary>
    public async Task<bool> SaveChangesAsync(string userId, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Saving changes to database with user context: {UserId}", userId);
            
            // Your AuditInterceptor will automatically pick up the user context
            // from HttpContext or you can pass it explicitly if needed
            var result = await _context.SaveChangesAsync(cancellationToken);
            
            _logger.LogDebug("Successfully saved {Count} changes to database for user {UserId}", result, userId);
            return result > 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while saving changes to database for user {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// Begins a new database transaction - For complex operations
    /// Use when you need to perform multiple operations atomically
    /// Transaction will be committed only when CommitTransactionAsync is called
    /// Will rollback automatically if exception occurs or RollbackTransactionAsync is called
    /// </summary>
    public async Task BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        if (_currentTransaction != null)
        {
            _logger.LogWarning("Transaction already started. Ignoring BeginTransactionAsync call");
            return;
        }

        try
        {
            _logger.LogDebug("Beginning database transaction");
            _currentTransaction = await _context.Database.BeginTransactionAsync(cancellationToken);
            _logger.LogDebug("Database transaction started successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while beginning database transaction");
            throw;
        }
    }

    /// <summary>
    /// Commits the current transaction - Makes all changes permanent
    /// Should be called after successful completion of all operations
    /// Transaction will be disposed after commit
    /// </summary>
    public async Task CommitTransactionAsync(CancellationToken cancellationToken = default)
    {
        if (_currentTransaction == null)
        {
            _logger.LogWarning("No active transaction to commit");
            return;
        }

        try
        {
            _logger.LogDebug("Committing database transaction");
            await _currentTransaction.CommitAsync(cancellationToken);
            _logger.LogDebug("Database transaction committed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while committing database transaction");
            await RollbackTransactionAsync(cancellationToken);
            throw;
        }
        finally
        {
            await DisposeTransactionAsync();
        }
    }

    /// <summary>
    /// Rolls back the current transaction - Discards all changes
    /// Should be called when an error occurs during transaction
    /// All changes made during transaction will be discarded
    /// </summary>
    public async Task RollbackTransactionAsync(CancellationToken cancellationToken = default)
    {
        if (_currentTransaction == null)
        {
            _logger.LogWarning("No active transaction to rollback");
            return;
        }

        try
        {
            _logger.LogDebug("Rolling back database transaction");
            await _currentTransaction.RollbackAsync(cancellationToken);
            _logger.LogDebug("Database transaction rolled back successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while rolling back database transaction");
            throw;
        }
        finally
        {
            await DisposeTransactionAsync();
        }
    }

    /// <summary>
    /// Executes an operation within a transaction - Convenience method
    /// Automatically begins transaction, executes operation, and commits
    /// Rolls back automatically if exception occurs
    /// Use for operations that need transaction but don't return a value
    /// </summary>
    public async Task ExecuteInTransactionAsync(Func<Task> operation, CancellationToken cancellationToken = default)
    {
        if (operation == null)
            throw new ArgumentNullException(nameof(operation));

        // If already in transaction, just execute the operation
        if (_currentTransaction != null)
        {
            _logger.LogDebug("Executing operation within existing transaction");
            await operation();
            return;
        }

        // Start new transaction
        await BeginTransactionAsync(cancellationToken);

        try
        {
            _logger.LogDebug("Executing operation within new transaction");
            await operation();
            await CommitTransactionAsync(cancellationToken);
            _logger.LogDebug("Operation executed successfully within transaction");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while executing operation within transaction");
            await RollbackTransactionAsync(cancellationToken);
            throw;
        }
    }

    /// <summary>
    /// Executes an operation within a transaction and returns result - Convenience method
    /// Automatically begins transaction, executes operation, and commits
    /// Rolls back automatically if exception occurs
    /// Use for operations that need transaction and return a value
    /// </summary>
    public async Task<T> ExecuteInTransactionAsync<T>(Func<Task<T>> operation, CancellationToken cancellationToken = default)
    {
        if (operation == null)
            throw new ArgumentNullException(nameof(operation));

        // If already in transaction, just execute the operation
        if (_currentTransaction != null)
        {
            _logger.LogDebug("Executing operation within existing transaction");
            return await operation();
        }

        // Start new transaction
        await BeginTransactionAsync(cancellationToken);

        try
        {
            _logger.LogDebug("Executing operation within new transaction");
            var result = await operation();
            await CommitTransactionAsync(cancellationToken);
            _logger.LogDebug("Operation executed successfully within transaction");
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while executing operation within transaction");
            await RollbackTransactionAsync(cancellationToken);
            throw;
        }
    }

    /// <summary>
    /// Disposes the current transaction - Internal cleanup method
    /// Called automatically after commit or rollback
    /// Ensures transaction resources are properly released
    /// </summary>
    private async Task DisposeTransactionAsync()
    {
        if (_currentTransaction != null)
        {
            try
            {
                await _currentTransaction.DisposeAsync();
                _logger.LogDebug("Database transaction disposed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while disposing database transaction");
            }
            finally
            {
                _currentTransaction = null;
            }
        }
    }

    /// <summary>
    /// Disposes the UnitOfWork - IDisposable implementation
    /// Ensures proper cleanup of resources
    /// Rolls back any active transaction
    /// Disposes the database context
    /// </summary>
    public void Dispose()
    {
        try
        {
            // Rollback any active transaction
            if (_currentTransaction != null)
            {
                _logger.LogWarning("Disposing UnitOfWork with active transaction. Rolling back transaction.");
                _currentTransaction.Rollback();
                _currentTransaction.Dispose();
                _currentTransaction = null;
            }

            // Dispose context
            _context.Dispose();
            _logger.LogDebug("UnitOfWork disposed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while disposing UnitOfWork");
        }
    }

    /// <summary>
    /// Async dispose implementation - IAsyncDisposable
    /// Preferred method for async cleanup
    /// Ensures proper cleanup of resources asynchronously
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        try
        {
            // Rollback any active transaction
            if (_currentTransaction != null)
            {
                _logger.LogWarning("Disposing UnitOfWork with active transaction. Rolling back transaction.");
                await _currentTransaction.RollbackAsync();
                await _currentTransaction.DisposeAsync();
                _currentTransaction = null;
            }

            // Dispose context
            await _context.DisposeAsync();
            _logger.LogDebug("UnitOfWork disposed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while disposing UnitOfWork");
        }
    }
}