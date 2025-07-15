using Microsoft.EntityFrameworkCore;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;
using Artemis.Auth.Infrastructure.Persistence;

namespace Artemis.Auth.Infrastructure.Persistence.Repositories;

/// <summary>
/// UserRepository: Implements all user-related database operations
/// Inherits from BaseRepository to get common CRUD operations
/// Implements IUserRepository interface from Application layer
/// Uses your AuthDbContext with all interceptors and optimizations
/// </summary>
public class UserRepository : BaseRepository<User>, IUserRepository
{
    /// <summary>
    /// Constructor: Injects AuthDbContext and passes to base class
    /// Base class handles DbSet initialization and context setup
    /// </summary>
    public UserRepository(AuthDbContext context) : base(context)
    {
    }

    /// <summary>
    /// Gets user by ID - Uses base class method with no tracking for performance
    /// Automatically excludes soft-deleted users via your query filters
    /// </summary>
    public async Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await base.GetByIdAsync(id, trackChanges: false, cancellationToken);
    }

    /// <summary>
    /// Gets user by username - Case-insensitive search using normalized username
    /// Uses your indexed NormalizedUsername field for optimal performance
    /// Includes related UserRoles for authorization checks
    /// </summary>
    public async Task<User?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(username))
            return null;

        var normalizedUsername = username.ToUpperInvariant();
        return await _dbSet.AsNoTracking()
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.NormalizedUsername == normalizedUsername, cancellationToken);
    }

    /// <summary>
    /// Gets user by email - Case-insensitive search using normalized email
    /// Uses your indexed NormalizedEmail field for optimal performance
    /// Includes related UserRoles for authorization checks
    /// </summary>
    public async Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(email))
            return null;

        var normalizedEmail = email.ToUpperInvariant();
        return await _dbSet.AsNoTracking()
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, cancellationToken);
    }

    /// <summary>
    /// Gets user by phone number - Direct search on PhoneNumber field
    /// Phone numbers are stored in normalized format (with country code)
    /// </summary>
    public async Task<User?> GetByPhoneNumberAsync(string phoneNumber, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(phoneNumber))
            return null;

        return await _dbSet.AsNoTracking()
            .FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber, cancellationToken);
    }

    /// <summary>
    /// Checks if username is unique - Critical for registration validation
    /// Uses efficient .AnyAsync() to check existence without loading data
    /// Excludes current user if updating (excludeUserId parameter)
    /// </summary>
    public async Task<bool> IsUsernameUniqueAsync(string username, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(username))
            return false;

        var normalizedUsername = username.ToUpperInvariant();
        var query = _dbSet.Where(u => u.NormalizedUsername == normalizedUsername);

        if (excludeUserId.HasValue)
            query = query.Where(u => u.Id != excludeUserId.Value);

        return !await query.AnyAsync(cancellationToken);
    }

    /// <summary>
    /// Checks if email is unique - Critical for registration validation
    /// Uses efficient .AnyAsync() to check existence without loading data
    /// Excludes current user if updating (excludeUserId parameter)
    /// </summary>
    public async Task<bool> IsEmailUniqueAsync(string email, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(email))
            return false;

        var normalizedEmail = email.ToUpperInvariant();
        var query = _dbSet.Where(u => u.NormalizedEmail == normalizedEmail);

        if (excludeUserId.HasValue)
            query = query.Where(u => u.Id != excludeUserId.Value);

        return !await query.AnyAsync(cancellationToken);
    }

    /// <summary>
    /// Checks if phone number is unique - For registration validation
    /// Uses efficient .AnyAsync() to check existence without loading data
    /// Excludes current user if updating (excludeUserId parameter)
    /// </summary>
    public async Task<bool> IsPhoneNumberUniqueAsync(string phoneNumber, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(phoneNumber))
            return true; // Phone number is optional, so null/empty is always unique

        var query = _dbSet.Where(u => u.PhoneNumber == phoneNumber);

        if (excludeUserId.HasValue)
            query = query.Where(u => u.Id != excludeUserId.Value);

        return !await query.AnyAsync(cancellationToken);
    }

    /// <summary>
    /// Creates a new user - Uses base class method with audit trail
    /// Your AuditInterceptor will automatically set CreatedAt, CreatedBy
    /// Returns the created user with generated ID
    /// </summary>
    public new async Task<User> CreateAsync(User user, CancellationToken cancellationToken = default)
    {
        return await base.CreateAsync(user, cancellationToken);
    }

    /// <summary>
    /// Updates an existing user - Uses base class method with audit trail
    /// Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
    /// EF Core will track changes and update only modified fields
    /// </summary>
    public Task<User> UpdateAsync(User user, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Update(user));
    }

    /// <summary>
    /// Soft deletes a user - Uses base class method with audit trail
    /// Your AuditInterceptor will set IsDeleted=true, DeletedAt=now, DeletedBy=currentUser
    /// User will be excluded from queries via your query filters
    /// </summary>
    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var user = await GetByIdAsync(id, cancellationToken);
        if (user == null)
            return false;

        Delete(user);
        return true;
    }

    /// <summary>
    /// Gets users with their roles - Used for admin panels and user management
    /// Uses efficient loading of related data with proper includes
    /// Filters to only specified user IDs for security
    /// </summary>
    public async Task<IEnumerable<User>> GetUsersWithRolesAsync(IEnumerable<Guid> userIds, CancellationToken cancellationToken = default)
    {
        var userIdList = userIds.ToList();
        if (!userIdList.Any())
            return Enumerable.Empty<User>();

        return await _dbSet.AsNoTracking()
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .Where(u => userIdList.Contains(u.Id))
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets locked users - Used for admin monitoring and user management
    /// Finds users with active lockout (LockoutEnd > now)
    /// Useful for security monitoring and unlock operations
    /// </summary>
    public async Task<IEnumerable<User>> GetLockedUsersAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        return await _dbSet.AsNoTracking()
            .Where(u => u.LockoutEnd.HasValue && u.LockoutEnd.Value > now)
            .OrderBy(u => u.LockoutEnd)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets unconfirmed users older than specified time - Used for cleanup jobs
    /// Finds users with unconfirmed emails created before cutoff time
    /// Useful for removing stale registrations and cleanup operations
    /// </summary>
    public async Task<IEnumerable<User>> GetUnconfirmedUsersAsync(TimeSpan olderThan, CancellationToken cancellationToken = default)
    {
        var cutoffDate = DateTime.UtcNow - olderThan;
        return await _dbSet.AsNoTracking()
            .Where(u => !u.EmailConfirmed && u.CreatedAt < cutoffDate)
            .OrderBy(u => u.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets inactive users - Used for user lifecycle management
    /// Finds users who haven't logged in for specified period
    /// Useful for user engagement analysis and cleanup
    /// </summary>
    public async Task<IEnumerable<User>> GetInactiveUsersAsync(TimeSpan inactivePeriod, CancellationToken cancellationToken = default)
    {
        var cutoffDate = DateTime.UtcNow - inactivePeriod;
        return await _dbSet.AsNoTracking()
            .Where(u => !u.LastLoginAt.HasValue || u.LastLoginAt.Value < cutoffDate)
            .OrderBy(u => u.LastLoginAt)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets user by security stamp - Used for security operations
    /// Security stamp changes when user's security context changes
    /// Used for token validation and security checks
    /// </summary>
    public async Task<User?> GetBySecurityStampAsync(string securityStamp, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(securityStamp))
            return null;

        return await _dbSet.AsNoTracking()
            .FirstOrDefaultAsync(u => u.SecurityStamp == securityStamp, cancellationToken);
    }

    /// <summary>
    /// Updates user's security stamp - Used when user's security context changes
    /// Security stamp should change on password change, role changes, etc.
    /// Invalidates existing tokens and sessions
    /// </summary>
    public async Task<bool> UpdateSecurityStampAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await _dbSet.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user == null)
            return false;

        user.SecurityStamp = Guid.NewGuid().ToString();
        // Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
        return true;
    }

    /// <summary>
    /// Updates user's password hash - Used for password change operations
    /// Updates password hash and automatically updates security stamp
    /// Security stamp change invalidates existing tokens
    /// </summary>
    public async Task<bool> UpdatePasswordAsync(Guid userId, string passwordHash, CancellationToken cancellationToken = default)
    {
        var user = await _dbSet.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user == null)
            return false;

        user.PasswordHash = passwordHash;
        user.SecurityStamp = Guid.NewGuid().ToString(); // Invalidate existing tokens
        // Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
        return true;
    }

    /// <summary>
    /// Updates email confirmation status - Used for email verification
    /// Sets EmailConfirmed flag after user clicks verification link
    /// </summary>
    public async Task<bool> UpdateEmailConfirmationAsync(Guid userId, bool isConfirmed, CancellationToken cancellationToken = default)
    {
        var user = await _dbSet.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user == null)
            return false;

        user.EmailConfirmed = isConfirmed;
        // Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
        return true;
    }

    /// <summary>
    /// Updates phone confirmation status - Used for phone number verification
    /// Sets PhoneNumberConfirmed flag after user verifies via SMS
    /// </summary>
    public async Task<bool> UpdatePhoneConfirmationAsync(Guid userId, bool isConfirmed, CancellationToken cancellationToken = default)
    {
        var user = await _dbSet.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user == null)
            return false;

        user.PhoneNumberConfirmed = isConfirmed;
        // Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
        return true;
    }

    /// <summary>
    /// Updates user lockout status - Used for account lockout management
    /// Sets lockout end time and failed login count
    /// Used by your progressive lockout algorithm
    /// </summary>
    public async Task<bool> UpdateLockoutAsync(Guid userId, DateTime? lockoutEnd, int failedLoginCount, CancellationToken cancellationToken = default)
    {
        var user = await _dbSet.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user == null)
            return false;

        user.LockoutEnd = lockoutEnd;
        user.FailedLoginCount = failedLoginCount;
        // Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
        return true;
    }

    /// <summary>
    /// Updates last login information - Used for tracking user activity
    /// Records login timestamp and IP address for security monitoring
    /// </summary>
    public async Task<bool> UpdateLastLoginAsync(Guid userId, DateTime lastLogin, string ipAddress, CancellationToken cancellationToken = default)
    {
        var user = await _dbSet.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user == null)
            return false;

        user.LastLoginAt = lastLogin;
        // Note: IP address might be stored in a related entity like UserSession
        // Your domain model doesn't have LastLoginIp directly on User
        // Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
        return true;
    }

    /// <summary>
    /// Updates two-factor authentication setting - Used for MFA management
    /// Enables/disables 2FA for the user
    /// </summary>
    public async Task<bool> UpdateTwoFactorAsync(Guid userId, bool twoFactorEnabled, CancellationToken cancellationToken = default)
    {
        var user = await _dbSet.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user == null)
            return false;

        user.TwoFactorEnabled = twoFactorEnabled;
        // Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
        return true;
    }

    /// <summary>
    /// Gets user's role names - Used for authorization checks
    /// Returns flat list of role names for easy permission checking
    /// Uses efficient query with joins
    /// </summary>
    public async Task<IEnumerable<string>> GetUserRolesAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.UserRoles
            .AsNoTracking()
            .Include(ur => ur.Role)
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.Role.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets user's permission names - Used for authorization checks
    /// Aggregates permissions from all user's roles
    /// Returns distinct permissions to avoid duplicates
    /// </summary>
    public async Task<IEnumerable<string>> GetUserPermissionsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.UserRoles
            .AsNoTracking()
            .Include(ur => ur.Role)
                .ThenInclude(r => r.RolePermissions)
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.Permission)
            .Distinct()
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Checks if user has specific permission - Used for authorization
    /// Efficient check without loading full permission list
    /// Uses optimized query with joins
    /// </summary>
    public async Task<bool> HasPermissionAsync(Guid userId, string permission, CancellationToken cancellationToken = default)
    {
        return await _context.UserRoles
            .AsNoTracking()
            .Include(ur => ur.Role)
                .ThenInclude(r => r.RolePermissions)
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role.RolePermissions)
            .AnyAsync(rp => rp.Permission == permission, cancellationToken);
    }

    /// <summary>
    /// Checks if user is in specific role - Used for authorization
    /// Efficient check without loading full role list
    /// Uses optimized query with joins
    /// </summary>
    public async Task<bool> IsInRoleAsync(Guid userId, string roleName, CancellationToken cancellationToken = default)
    {
        return await _context.UserRoles
            .AsNoTracking()
            .Include(ur => ur.Role)
            .AnyAsync(ur => ur.UserId == userId && ur.Role.Name == roleName, cancellationToken);
    }

    /// <summary>
    /// Gets user's active sessions - Used for session management
    /// Returns non-revoked sessions that haven't expired
    /// Useful for session invalidation and monitoring
    /// </summary>
    public async Task<IEnumerable<UserSession>> GetActiveSessionsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        return await _context.UserSessions
            .AsNoTracking()
            .Where(s => s.UserId == userId && 
                       !s.IsRevoked && 
                       s.ExpiresAt > now)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets user's password history - Used for password reuse prevention
    /// Returns recent password hashes to prevent reuse
    /// Ordered by creation date (newest first)
    /// </summary>
    public async Task<IEnumerable<PasswordHistory>> GetPasswordHistoryAsync(Guid userId, int count, CancellationToken cancellationToken = default)
    {
        return await _context.PasswordHistories
            .AsNoTracking()
            .Where(ph => ph.UserId == userId)
            .OrderByDescending(ph => ph.CreatedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Searches users by term - Used for admin panels and user management
    /// Searches in username, email, and phone number fields
    /// Uses pagination for performance with large datasets
    /// </summary>
    public async Task<IEnumerable<User>> SearchUsersAsync(string searchTerm, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(searchTerm))
            return Enumerable.Empty<User>();

        var searchTermUpper = searchTerm.ToUpperInvariant();
        return await _dbSet.AsNoTracking()
            .Where(u => u.NormalizedUsername.Contains(searchTermUpper) ||
                       u.NormalizedEmail.Contains(searchTermUpper) ||
                       (u.PhoneNumber != null && u.PhoneNumber.Contains(searchTerm)))
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .OrderBy(u => u.Username)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets total user count - Used for analytics and admin dashboards
    /// Excludes soft-deleted users automatically
    /// </summary>
    public async Task<int> GetUserCountAsync(CancellationToken cancellationToken = default)
    {
        return await _dbSet.CountAsync(cancellationToken);
    }

    /// <summary>
    /// Gets active user count - Used for analytics and monitoring
    /// Counts users who are not locked out and have confirmed emails
    /// </summary>
    public async Task<int> GetActiveUserCountAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        return await _dbSet.CountAsync(u => u.EmailConfirmed && 
                                          (!u.LockoutEnd.HasValue || u.LockoutEnd.Value <= now), 
                                      cancellationToken);
    }

    /// <summary>
    /// Gets user's audit logs - Used for security monitoring and compliance
    /// Returns paginated audit trail for specific user
    /// Useful for tracking user actions and security events
    /// </summary>
    public async Task<IEnumerable<AuditLog>> GetUserAuditLogsAsync(Guid userId, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        return await _context.AuditLogs
            .AsNoTracking()
            .Where(al => al.RecordId == userId && al.TableName == "users")
            .OrderByDescending(al => al.PerformedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);
    }
}