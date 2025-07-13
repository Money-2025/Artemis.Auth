using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> builder)
    {
        builder.ToTable("roles");
        
        builder.HasKey(r => r.Id);
        
        builder.Property(r => r.Name)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(r => r.NormalizedName)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(r => r.Description)
            .HasColumnType("text");
            
        builder.Property(r => r.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(r => r.CreatedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(r => r.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(r => r.NormalizedName)
            .IsUnique()
            .HasFilter("\"is_deleted\" = false");
            
        builder.HasIndex(r => r.IsDeleted);

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