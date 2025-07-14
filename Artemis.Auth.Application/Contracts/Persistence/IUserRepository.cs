using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Application.Contracts.Persistence;

public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<User?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default);
    Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<User?> GetByPhoneNumberAsync(string phoneNumber, CancellationToken cancellationToken = default);
    Task<bool> IsUsernameUniqueAsync(string username, Guid? excludeUserId = null, CancellationToken cancellationToken = default);
    Task<bool> IsEmailUniqueAsync(string email, Guid? excludeUserId = null, CancellationToken cancellationToken = default);
    Task<bool> IsPhoneNumberUniqueAsync(string phoneNumber, Guid? excludeUserId = null, CancellationToken cancellationToken = default);
    Task<User> CreateAsync(User user, CancellationToken cancellationToken = default);
    Task<User> UpdateAsync(User user, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken = default);
    Task<IEnumerable<User>> GetUsersWithRolesAsync(IEnumerable<Guid> userIds, CancellationToken cancellationToken = default);
    Task<IEnumerable<User>> GetLockedUsersAsync(CancellationToken cancellationToken = default);
    Task<IEnumerable<User>> GetUnconfirmedUsersAsync(TimeSpan olderThan, CancellationToken cancellationToken = default);
    Task<IEnumerable<User>> GetInactiveUsersAsync(TimeSpan inactivePeriod, CancellationToken cancellationToken = default);
    Task<User?> GetBySecurityStampAsync(string securityStamp, CancellationToken cancellationToken = default);
    Task<bool> UpdateSecurityStampAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<bool> UpdatePasswordAsync(Guid userId, string passwordHash, CancellationToken cancellationToken = default);
    Task<bool> UpdateEmailConfirmationAsync(Guid userId, bool isConfirmed, CancellationToken cancellationToken = default);
    Task<bool> UpdatePhoneConfirmationAsync(Guid userId, bool isConfirmed, CancellationToken cancellationToken = default);
    Task<bool> UpdateLockoutAsync(Guid userId, DateTime? lockoutEnd, int failedLoginCount, CancellationToken cancellationToken = default);
    Task<bool> UpdateLastLoginAsync(Guid userId, DateTime lastLogin, string ipAddress, CancellationToken cancellationToken = default);
    Task<bool> UpdateTwoFactorAsync(Guid userId, bool twoFactorEnabled, CancellationToken cancellationToken = default);
    Task<IEnumerable<string>> GetUserRolesAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<IEnumerable<string>> GetUserPermissionsAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<bool> HasPermissionAsync(Guid userId, string permission, CancellationToken cancellationToken = default);
    Task<bool> IsInRoleAsync(Guid userId, string roleName, CancellationToken cancellationToken = default);
    Task<IEnumerable<UserSession>> GetActiveSessionsAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<IEnumerable<PasswordHistory>> GetPasswordHistoryAsync(Guid userId, int count, CancellationToken cancellationToken = default);
    Task<IEnumerable<User>> SearchUsersAsync(string searchTerm, int page, int pageSize, CancellationToken cancellationToken = default);
    Task<int> GetUserCountAsync(CancellationToken cancellationToken = default);
    Task<int> GetActiveUserCountAsync(CancellationToken cancellationToken = default);
    Task<IEnumerable<AuditLog>> GetUserAuditLogsAsync(Guid userId, int page, int pageSize, CancellationToken cancellationToken = default);
}