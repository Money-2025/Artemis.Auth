using Microsoft.EntityFrameworkCore;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Persistence;

namespace Artemis.Auth.Infrastructure.Persistence.Repositories;

/// <summary>
/// RoleRepository: Implements all role and permission-related database operations
/// Inherits from BaseRepository to get common CRUD operations
/// Implements IRoleRepository interface from Application layer
/// Handles role-based access control (RBAC) operations
/// </summary>
public class RoleRepository : BaseRepository<Role>, IRoleRepository
{
    /// <summary>
    /// Constructor: Injects AuthDbContext and passes to base class
    /// Base class handles DbSet initialization and context setup
    /// </summary>
    public RoleRepository(AuthDbContext context) : base(context)
    {
    }

    /// <summary>
    /// Gets role by ID - Uses base class method with no tracking for performance
    /// Automatically excludes soft-deleted roles via your query filters
    /// </summary>
    public async Task<Role?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await base.GetByIdAsync(id, trackChanges: false, cancellationToken);
    }

    /// <summary>
    /// Gets role by name - Case-insensitive search using normalized name
    /// Uses your indexed NormalizedName field for optimal performance
    /// Includes related permissions for complete role information
    /// </summary>
    public async Task<Role?> GetByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(name))
            return null;

        var normalizedName = name.ToUpperInvariant();
        return await _dbSet.AsNoTracking()
            .Include(r => r.RolePermissions)
            .FirstOrDefaultAsync(r => r.NormalizedName == normalizedName, cancellationToken);
    }

    /// <summary>
    /// Gets all roles - Used for admin panels and role management
    /// Includes permission count for each role
    /// Orders by role name for consistent display
    /// </summary>
    public async Task<IEnumerable<Role>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _dbSet.AsNoTracking()
            .Include(r => r.RolePermissions)
            .OrderBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets roles for specific user - Used for user management and authorization
    /// Joins through UserRoles table to get user's assigned roles
    /// Returns roles with their permissions
    /// </summary>
    public async Task<IEnumerable<Role>> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.UserRoles
            .AsNoTracking()
            .Include(ur => ur.Role)
                .ThenInclude(r => r.RolePermissions)
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.Role)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Checks if role name is unique - Critical for role creation/update validation
    /// Uses efficient .AnyAsync() to check existence without loading data
    /// Excludes current role if updating (excludeRoleId parameter)
    /// </summary>
    public async Task<bool> IsNameUniqueAsync(string name, Guid? excludeRoleId = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(name))
            return false;

        var normalizedName = name.ToUpperInvariant();
        var query = _dbSet.Where(r => r.NormalizedName == normalizedName);

        if (excludeRoleId.HasValue)
            query = query.Where(r => r.Id != excludeRoleId.Value);

        return !await query.AnyAsync(cancellationToken);
    }

    /// <summary>
    /// Creates a new role - Uses base class method with audit trail
    /// Your AuditInterceptor will automatically set CreatedAt, CreatedBy
    /// Returns the created role with generated ID
    /// </summary>
    public new async Task<Role> CreateAsync(Role role, CancellationToken cancellationToken = default)
    {
        return await base.CreateAsync(role, cancellationToken);
    }

    /// <summary>
    /// Updates an existing role - Uses base class method with audit trail
    /// Your AuditInterceptor will automatically set ModifiedAt, ModifiedBy
    /// EF Core will track changes and update only modified fields
    /// </summary>
    public Task<Role> UpdateAsync(Role role, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Update(role));
    }

    /// <summary>
    /// Soft deletes a role - Uses base class method with audit trail
    /// Your AuditInterceptor will set IsDeleted=true, DeletedAt=now, DeletedBy=currentUser
    /// Role will be excluded from queries via your query filters
    /// Should check if role is assigned to users before deletion
    /// </summary>
    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var role = await GetByIdAsync(id, cancellationToken);
        if (role == null)
            return false;

        Delete(role);
        return true;
    }

    /// <summary>
    /// Assigns a role to a user - Creates UserRole relationship
    /// Checks if assignment already exists to avoid duplicates
    /// Records who made the assignment and when
    /// </summary>
    public async Task<bool> AssignRoleToUserAsync(Guid userId, Guid roleId, Guid? assignedBy = null, CancellationToken cancellationToken = default)
    {
        // Check if user and role exist
        var userExists = await _context.Users.AnyAsync(u => u.Id == userId, cancellationToken);
        var roleExists = await _dbSet.AnyAsync(r => r.Id == roleId, cancellationToken);

        if (!userExists || !roleExists)
            return false;

        // Check if assignment already exists
        var existingAssignment = await _context.UserRoles
            .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == roleId, cancellationToken);

        if (existingAssignment != null)
            return false; // Already assigned

        // Create new assignment
        var userRole = new UserRole
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            RoleId = roleId,
            AssignedAt = DateTime.UtcNow,
            AssignedBy = assignedBy,
            CreatedAt = DateTime.UtcNow,
            CreatedBy = assignedBy,
            IsDeleted = false
        };

        await _context.UserRoles.AddAsync(userRole, cancellationToken);
        return true;
    }

    /// <summary>
    /// Removes a role from a user - Soft deletes UserRole relationship
    /// Uses soft delete so assignment history is preserved
    /// Your AuditInterceptor will track the removal
    /// </summary>
    public async Task<bool> RemoveRoleFromUserAsync(Guid userId, Guid roleId, CancellationToken cancellationToken = default)
    {
        var userRole = await _context.UserRoles
            .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == roleId, cancellationToken);

        if (userRole == null)
            return false;

        // Soft delete the assignment
        userRole.IsDeleted = true;
        userRole.DeletedAt = DateTime.UtcNow;
        // Your AuditInterceptor will set DeletedBy automatically

        return true;
    }

    /// <summary>
    /// Replaces all user's roles with new set - Atomic operation
    /// Removes all existing roles and assigns new ones
    /// Useful for bulk role updates from admin panels
    /// </summary>
    public async Task<bool> ReplaceUserRolesAsync(Guid userId, IEnumerable<Guid> roleIds, Guid? assignedBy = null, CancellationToken cancellationToken = default)
    {
        var roleIdList = roleIds.ToList();

        // Verify user exists
        var userExists = await _context.Users.AnyAsync(u => u.Id == userId, cancellationToken);
        if (!userExists)
            return false;

        // Verify all roles exist
        var existingRoleIds = await _dbSet
            .Where(r => roleIdList.Contains(r.Id))
            .Select(r => r.Id)
            .ToListAsync(cancellationToken);

        if (existingRoleIds.Count != roleIdList.Count)
            return false; // Some roles don't exist

        // Remove all existing role assignments (soft delete)
        var existingUserRoles = await _context.UserRoles
            .Where(ur => ur.UserId == userId)
            .ToListAsync(cancellationToken);

        foreach (var userRole in existingUserRoles)
        {
            userRole.IsDeleted = true;
            userRole.DeletedAt = DateTime.UtcNow;
            // Your AuditInterceptor will set DeletedBy automatically
        }

        // Add new role assignments
        foreach (var roleId in roleIdList)
        {
            var userRole = new UserRole
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                RoleId = roleId,
                AssignedAt = DateTime.UtcNow,
                AssignedBy = assignedBy,
                CreatedAt = DateTime.UtcNow,
                CreatedBy = assignedBy,
                IsDeleted = false
            };

            await _context.UserRoles.AddAsync(userRole, cancellationToken);
        }

        return true;
    }

    /// <summary>
    /// Gets all permissions for a role - Used for role management
    /// Returns flat list of permission names
    /// Useful for displaying role capabilities
    /// </summary>
    public async Task<IEnumerable<string>> GetRolePermissionsAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        return await _context.RolePermissions
            .AsNoTracking()
            .Where(rp => rp.RoleId == roleId)
            .Select(rp => rp.Permission)
            .OrderBy(p => p)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets all permissions for a role by name - Used for authorization
    /// Returns flat list of permission names
    /// More efficient than loading full role object
    /// </summary>
    public async Task<IEnumerable<string>> GetRolePermissionsByNameAsync(string roleName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(roleName))
            return Enumerable.Empty<string>();

        var normalizedName = roleName.ToUpperInvariant();
        return await _context.RolePermissions
            .AsNoTracking()
            .Include(rp => rp.Role)
            .Where(rp => rp.Role.NormalizedName == normalizedName)
            .Select(rp => rp.Permission)
            .OrderBy(p => p)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Adds a permission to a role - Creates RolePermission relationship
    /// Checks if permission already exists to avoid duplicates
    /// Used for dynamic permission management
    /// </summary>
    public async Task<bool> AddPermissionToRoleAsync(Guid roleId, string permission, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(permission))
            return false;

        // Check if role exists
        var roleExists = await _dbSet.AnyAsync(r => r.Id == roleId, cancellationToken);
        if (!roleExists)
            return false;

        // Check if permission already exists for this role
        var existingPermission = await _context.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.Permission == permission, cancellationToken);

        if (existingPermission != null)
            return false; // Already exists

        // Create new permission assignment
        var rolePermission = new RolePermission
        {
            Id = Guid.NewGuid(),
            RoleId = roleId,
            Permission = permission,
            CreatedAt = DateTime.UtcNow,
            IsDeleted = false
        };

        await _context.RolePermissions.AddAsync(rolePermission, cancellationToken);
        return true;
    }

    /// <summary>
    /// Removes a permission from a role - Soft deletes RolePermission
    /// Uses soft delete so permission history is preserved
    /// Your AuditInterceptor will track the removal
    /// </summary>
    public async Task<bool> RemovePermissionFromRoleAsync(Guid roleId, string permission, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(permission))
            return false;

        var rolePermission = await _context.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.Permission == permission, cancellationToken);

        if (rolePermission == null)
            return false;

        // Soft delete the permission assignment
        rolePermission.IsDeleted = true;
        rolePermission.DeletedAt = DateTime.UtcNow;
        // Your AuditInterceptor will set DeletedBy automatically

        return true;
    }

    /// <summary>
    /// Replaces all role's permissions with new set - Atomic operation
    /// Removes all existing permissions and assigns new ones
    /// Useful for bulk permission updates from admin panels
    /// </summary>
    public async Task<bool> ReplaceRolePermissionsAsync(Guid roleId, IEnumerable<string> permissions, CancellationToken cancellationToken = default)
    {
        var permissionList = permissions.ToList();

        // Verify role exists
        var roleExists = await _dbSet.AnyAsync(r => r.Id == roleId, cancellationToken);
        if (!roleExists)
            return false;

        // Remove all existing permissions (soft delete)
        var existingPermissions = await _context.RolePermissions
            .Where(rp => rp.RoleId == roleId)
            .ToListAsync(cancellationToken);

        foreach (var rolePermission in existingPermissions)
        {
            rolePermission.IsDeleted = true;
            rolePermission.DeletedAt = DateTime.UtcNow;
            // Your AuditInterceptor will set DeletedBy automatically
        }

        // Add new permissions
        foreach (var permission in permissionList)
        {
            if (string.IsNullOrEmpty(permission))
                continue;

            var rolePermission = new RolePermission
            {
                Id = Guid.NewGuid(),
                RoleId = roleId,
                Permission = permission,
                CreatedAt = DateTime.UtcNow,
                IsDeleted = false
            };

            await _context.RolePermissions.AddAsync(rolePermission, cancellationToken);
        }

        return true;
    }

    /// <summary>
    /// Checks if role has specific permission - Used for authorization
    /// Efficient check without loading full permission list
    /// Uses optimized query
    /// </summary>
    public async Task<bool> HasPermissionAsync(Guid roleId, string permission, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(permission))
            return false;

        return await _context.RolePermissions
            .AsNoTracking()
            .AnyAsync(rp => rp.RoleId == roleId && rp.Permission == permission, cancellationToken);
    }

    /// <summary>
    /// Gets all users assigned to a role - Used for role management
    /// Returns users with their basic information
    /// Useful for understanding role usage
    /// </summary>
    public async Task<IEnumerable<User>> GetUsersInRoleAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        return await _context.UserRoles
            .AsNoTracking()
            .Include(ur => ur.User)
            .Where(ur => ur.RoleId == roleId)
            .Select(ur => ur.User)
            .OrderBy(u => u.Username)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets all users assigned to a role by name - Used for authorization
    /// Returns users with their basic information
    /// More efficient than loading full role object
    /// </summary>
    public async Task<IEnumerable<User>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(roleName))
            return Enumerable.Empty<User>();

        var normalizedName = roleName.ToUpperInvariant();
        return await _context.UserRoles
            .AsNoTracking()
            .Include(ur => ur.User)
            .Include(ur => ur.Role)
            .Where(ur => ur.Role.NormalizedName == normalizedName)
            .Select(ur => ur.User)
            .OrderBy(u => u.Username)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets count of users in a role - Used for analytics and role management
    /// Efficient count without loading user objects
    /// Useful for understanding role distribution
    /// </summary>
    public async Task<int> GetUserCountInRoleAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        return await _context.UserRoles
            .AsNoTracking()
            .CountAsync(ur => ur.RoleId == roleId, cancellationToken);
    }

    /// <summary>
    /// Searches roles by term - Used for admin panels and role management
    /// Searches in role name and description fields
    /// Uses pagination for performance with large datasets
    /// </summary>
    public async Task<IEnumerable<Role>> SearchRolesAsync(string searchTerm, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(searchTerm))
            return Enumerable.Empty<Role>();

        var searchTermUpper = searchTerm.ToUpperInvariant();
        return await _dbSet.AsNoTracking()
            .Include(r => r.RolePermissions)
            .Where(r => r.NormalizedName.Contains(searchTermUpper) ||
                       (r.Description != null && r.Description.ToUpper().Contains(searchTermUpper)))
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .OrderBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets total role count - Used for analytics and admin dashboards
    /// Excludes soft-deleted roles automatically
    /// </summary>
    public async Task<int> GetRoleCountAsync(CancellationToken cancellationToken = default)
    {
        return await _dbSet.CountAsync(cancellationToken);
    }

    /// <summary>
    /// Checks if role is assigned to any users - Used before role deletion
    /// Prevents deletion of roles that are still in use
    /// Returns true if role has active assignments
    /// </summary>
    public async Task<bool> IsRoleAssignedToUsersAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        return await _context.UserRoles
            .AsNoTracking()
            .AnyAsync(ur => ur.RoleId == roleId, cancellationToken);
    }

    /// <summary>
    /// Gets all available permissions in the system - Used for role management
    /// Returns distinct permissions from all roles
    /// Useful for permission management interfaces
    /// </summary>
    public async Task<IEnumerable<string>> GetAllPermissionsAsync(CancellationToken cancellationToken = default)
    {
        return await _context.RolePermissions
            .AsNoTracking()
            .Select(rp => rp.Permission)
            .Distinct()
            .OrderBy(p => p)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Gets permissions not assigned to a role - Used for permission management
    /// Returns available permissions that can be added to the role
    /// Useful for permission assignment interfaces
    /// </summary>
    public async Task<IEnumerable<string>> GetUnassignedPermissionsAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        // Get all permissions in the system
        var allPermissions = await GetAllPermissionsAsync(cancellationToken);
        
        // Get permissions already assigned to this role
        var assignedPermissions = await GetRolePermissionsAsync(roleId, cancellationToken);
        
        // Return the difference
        return allPermissions.Except(assignedPermissions).OrderBy(p => p);
    }
}