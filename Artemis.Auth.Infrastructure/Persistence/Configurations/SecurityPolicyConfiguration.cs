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
            .HasConversion<string>();
            
        builder.Property(sp => sp.Name)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(sp => sp.Parameters)
            .IsRequired()
            .HasColumnType("jsonb");
            
        builder.Property(sp => sp.ParametersVersion)
            .HasDefaultValue(1);
            
        builder.Property(sp => sp.IsActive)
            .HasDefaultValue(true);
    }
}