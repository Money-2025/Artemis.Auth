using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Application.Contracts.Persistence;

public interface IRoleRepository
{
    Task<Role?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<Role?> GetByNameAsync(string name, CancellationToken cancellationToken = default);
    Task<IEnumerable<Role>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IEnumerable<Role>> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<bool> IsNameUniqueAsync(string name, Guid? excludeRoleId = null, CancellationToken cancellationToken = default);
    Task<Role> CreateAsync(Role role, CancellationToken cancellationToken = default);
    Task<Role> UpdateAsync(Role role, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken = default);
    Task<bool> AssignRoleToUserAsync(Guid userId, Guid roleId, Guid? assignedBy = null, CancellationToken cancellationToken = default);
    Task<bool> RemoveRoleFromUserAsync(Guid userId, Guid roleId, CancellationToken cancellationToken = default);
    Task<bool> ReplaceUserRolesAsync(Guid userId, IEnumerable<Guid> roleIds, Guid? assignedBy = null, CancellationToken cancellationToken = default);
    Task<IEnumerable<string>> GetRolePermissionsAsync(Guid roleId, CancellationToken cancellationToken = default);
    Task<IEnumerable<string>> GetRolePermissionsByNameAsync(string roleName, CancellationToken cancellationToken = default);
    Task<bool> AddPermissionToRoleAsync(Guid roleId, string permission, CancellationToken cancellationToken = default);
    Task<bool> RemovePermissionFromRoleAsync(Guid roleId, string permission, CancellationToken cancellationToken = default);
    Task<bool> ReplaceRolePermissionsAsync(Guid roleId, IEnumerable<string> permissions, CancellationToken cancellationToken = default);
    Task<bool> HasPermissionAsync(Guid roleId, string permission, CancellationToken cancellationToken = default);
    Task<IEnumerable<User>> GetUsersInRoleAsync(Guid roleId, CancellationToken cancellationToken = default);
    Task<IEnumerable<User>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default);
    Task<int> GetUserCountInRoleAsync(Guid roleId, CancellationToken cancellationToken = default);
    Task<IEnumerable<Role>> SearchRolesAsync(string searchTerm, int page, int pageSize, CancellationToken cancellationToken = default);
    Task<int> GetRoleCountAsync(CancellationToken cancellationToken = default);
    Task<bool> IsRoleAssignedToUsersAsync(Guid roleId, CancellationToken cancellationToken = default);
    Task<IEnumerable<string>> GetAllPermissionsAsync(CancellationToken cancellationToken = default);
    Task<IEnumerable<string>> GetUnassignedPermissionsAsync(Guid roleId, CancellationToken cancellationToken = default);
}