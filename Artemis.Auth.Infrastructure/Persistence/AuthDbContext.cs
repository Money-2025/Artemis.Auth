using Microsoft.EntityFrameworkCore;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Infrastructure.Persistence;

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; }
    public DbSet<Role> Roles { get; set; }
    public DbSet<UserRole> UserRoles { get; set; }
    public DbSet<UserMfaMethod> UserMfaMethods { get; set; }
    public DbSet<TokenGrant> TokenGrants { get; set; }
    public DbSet<AuditLog> AuditLogs { get; set; }
    public DbSet<UserSession> UserSessions { get; set; }
    public DbSet<SecurityPolicy> SecurityPolicies { get; set; }
    public DbSet<PasswordHistory> PasswordHistories { get; set; }
    public DbSet<RolePermission> RolePermissions { get; set; }
    public DbSet<DeviceTrust> DeviceTrusts { get; set; }
}