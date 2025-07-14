using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class UserRoleConfiguration : BaseEntityConfiguration<UserRole>
{
    public UserRoleConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<UserRole> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("user_roles");
        
        builder.Property(ur => ur.UserId)
            .IsRequired();
            
        builder.Property(ur => ur.RoleId)
            .IsRequired();
            
        builder.Property(ur => ur.AssignedAt)
            .HasDefaultValueSql(GetCurrentTimestampSql());

        // UserRole-specific indexes
        builder.HasIndex(ur => new { ur.UserId, ur.RoleId })
            .IsUnique()
            .HasFilter(GetUniqueFilterSql("is_deleted"))
            .HasDatabaseName("IX_user_roles_UserId_RoleId");
            
        builder.HasIndex(ur => ur.UserId)
            .HasDatabaseName("IX_user_roles_UserId");
        builder.HasIndex(ur => ur.RoleId)
            .HasDatabaseName("IX_user_roles_RoleId");

        // Relationships are already defined in User and Role configurations
    }
}