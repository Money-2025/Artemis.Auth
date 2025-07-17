using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class RolePermissionConfiguration : BaseEntityConfiguration<RolePermission>
{
    public RolePermissionConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<RolePermission> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("role_permissions");
        
        builder.Property(rp => rp.RoleId)
            .IsRequired();
            
        builder.Property(rp => rp.Permission)
            .IsRequired()
            .HasMaxLength(256);

        // RolePermission-specific indexes
        builder.HasIndex(rp => new { rp.RoleId, rp.Permission })
            .IsUnique()
            .HasFilter(GetUniqueFilterSql("is_deleted"))
            .HasDatabaseName("ix_role_permissions_role_id_permission");
            
        builder.HasIndex(rp => rp.RoleId)
            .HasDatabaseName("ix_role_permissions_role_id");

        // Relationships are already defined in Role configuration
    }
}