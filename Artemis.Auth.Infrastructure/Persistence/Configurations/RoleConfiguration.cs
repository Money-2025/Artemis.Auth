using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class RoleConfiguration : BaseEntityConfiguration<Role>
{
    public RoleConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<Role> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("roles");
        
        builder.Property(r => r.Name)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(r => r.NormalizedName)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(r => r.Description)
            .HasColumnType("text");

        // Role-specific indexes
        builder.HasIndex(r => r.NormalizedName)
            .IsUnique()
            .HasFilter(GetUniqueFilterSql("is_deleted"))
            .HasDatabaseName("IX_roles_NormalizedName");

        // Relationships
        builder.HasMany(r => r.UserRoles)
            .WithOne(ur => ur.Role)
            .HasForeignKey(ur => ur.RoleId)
            .OnDelete(DeleteBehavior.Cascade);
            
        builder.HasMany(r => r.RolePermissions)
            .WithOne(rp => rp.Role)
            .HasForeignKey(rp => rp.RoleId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}