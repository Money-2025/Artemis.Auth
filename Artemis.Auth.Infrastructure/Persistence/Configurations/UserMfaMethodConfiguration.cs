using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class UserMfaMethodConfiguration : BaseEntityConfiguration<UserMfaMethod>
{
    public UserMfaMethodConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<UserMfaMethod> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("user_mfa_methods");
        
        builder.Property(umfa => umfa.UserId)
            .IsRequired();
            
        builder.Property(umfa => umfa.Type)
            .IsRequired()
            .HasConversion<string>();
            
        builder.Property(umfa => umfa.SecretKey)
            .HasMaxLength(500);
            
        builder.Property(umfa => umfa.IsEnabled)
            .HasDefaultValue(false);

        // UserMfaMethod-specific indexes
        builder.HasIndex(umfa => umfa.UserId)
            .HasDatabaseName("IX_user_mfa_methods_UserId");

        // Relationships are already defined in User configuration
    }
}