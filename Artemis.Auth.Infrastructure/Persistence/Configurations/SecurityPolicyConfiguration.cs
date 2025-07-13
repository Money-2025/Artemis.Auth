using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class SecurityPolicyConfiguration : IEntityTypeConfiguration<SecurityPolicy>
{
    public void Configure(EntityTypeBuilder<SecurityPolicy> builder)
    {
        builder.ToTable("security_policies");
        
        builder.HasKey(sp => sp.Id);
        
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
            
        builder.Property(sp => sp.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(sp => sp.CreatedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(sp => sp.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);
    }
}