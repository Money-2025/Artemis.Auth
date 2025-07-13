using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class RolePermissionConfiguration : IEntityTypeConfiguration<RolePermission>
{
    public void Configure(EntityTypeBuilder<RolePermission> builder)
    {
        builder.ToTable("role_permissions");
        
        builder.HasKey(rp => rp.Id);
        
        builder.Property(rp => rp.RoleId)
            .IsRequired();
            
        builder.Property(rp => rp.Permission)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(rp => rp.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(rp => rp.CreatedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(rp => rp.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(rp => new { rp.RoleId, rp.Permission })
            .IsUnique()
            .HasFilter("\"is_deleted\" = false");
            
        builder.HasIndex(rp => rp.RoleId);

        // Relationships are already defined in Role configuration
    }
}