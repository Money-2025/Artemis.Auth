using Microsoft.EntityFrameworkCore;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Persistence.Configurations;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence;

public class AuthDbContext : DbContext
{
    private readonly DatabaseConfiguration _databaseConfiguration;
    
    public AuthDbContext(DbContextOptions<AuthDbContext> options, DatabaseConfiguration databaseConfig) : base(options)
    {
        _databaseConfiguration = databaseConfig;
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

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfiguration(new UserConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new RoleConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new UserRoleConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new UserMfaMethodConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new TokenGrantConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new AuditLogConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new UserSessionConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new SecurityPolicyConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new PasswordHistoryConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new RolePermissionConfiguration(_databaseConfiguration));
        modelBuilder.ApplyConfiguration(new DeviceTrustConfiguration(_databaseConfiguration));
    }
}