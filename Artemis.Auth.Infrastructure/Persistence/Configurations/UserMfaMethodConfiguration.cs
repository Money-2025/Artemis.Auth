using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class UserMfaMethodConfiguration : IEntityTypeConfiguration<UserMfaMethod>
{
    public void Configure(EntityTypeBuilder<UserMfaMethod> builder)
    {
        builder.ToTable("user_mfa_methods");
        
        builder.HasKey(umfa => umfa.Id);
        
        builder.Property(umfa => umfa.UserId)
            .IsRequired();
            
        builder.Property(umfa => umfa.Type)
            .IsRequired()
            .HasConversion<string>();
            
        builder.Property(umfa => umfa.SecretKey)
            .HasMaxLength(500);
            
        builder.Property(umfa => umfa.IsEnabled)
            .HasDefaultValue(false);
            
        builder.Property(umfa => umfa.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(umfa => umfa.CreatedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(umfa => umfa.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(umfa => umfa.UserId);

        // Relationships are already defined in User configuration
    }
}