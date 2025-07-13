using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class UserRoleConfiguration : IEntityTypeConfiguration<UserRole>
{
    public void Configure(EntityTypeBuilder<UserRole> builder)
    {
        builder.ToTable("user_roles");
        
        builder.HasKey(ur => ur.Id);
        
        builder.Property(ur => ur.UserId)
            .IsRequired();
            
        builder.Property(ur => ur.RoleId)
            .IsRequired();
            
        builder.Property(ur => ur.AssignedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(ur => ur.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(ur => ur.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(ur => new { ur.UserId, ur.RoleId })
            .IsUnique()
            .HasFilter("\"is_deleted\" = false");
            
        builder.HasIndex(ur => ur.UserId);
        builder.HasIndex(ur => ur.RoleId);

        // Relationships are already defined in User and Role configurations
    }
}