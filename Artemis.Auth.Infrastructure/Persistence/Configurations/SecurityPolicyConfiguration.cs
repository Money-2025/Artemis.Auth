using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class SecurityPolicyConfiguration : BaseEntityConfiguration<SecurityPolicy>
{
    public SecurityPolicyConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<SecurityPolicy> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("security_policies");
        
        builder.Property(sp => sp.PolicyType)
            .IsRequired()
            .HasConversion(
                v => v.ToString().ToLowerInvariant(),
                v => Enum.Parse<SecurityPolicyType>(v, true))
            .HasMaxLength(50);
            
        builder.Property(sp => sp.Name)
            .IsRequired()
            .HasMaxLength(256);
            
        // Use PostgreSQL-specific JSON type only for PostgreSQL provider
        if (_databaseProvider == DatabaseProvider.PostgreSQL)
        {
            builder.Property(sp => sp.Parameters)
                .IsRequired()
                .HasColumnType("jsonb");
        }
        else
        {
            builder.Property(sp => sp.Parameters)
                .IsRequired()
                .HasColumnType("nvarchar(max)");
        }
            
        builder.Property(sp => sp.ParametersVersion)
            .HasDefaultValue(1);
            
        builder.Property(sp => sp.IsActive)
            .HasDefaultValue(true);
    }
}