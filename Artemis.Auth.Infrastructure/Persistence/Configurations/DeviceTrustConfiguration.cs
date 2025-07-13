using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class DeviceTrustConfiguration : IEntityTypeConfiguration<DeviceTrust>
{
    public void Configure(EntityTypeBuilder<DeviceTrust> builder)
    {
        builder.ToTable("device_trusts");
        
        builder.HasKey(dt => dt.Id);
        
        builder.Property(dt => dt.UserId)
            .IsRequired();
            
        builder.Property(dt => dt.DeviceName)
            .HasMaxLength(256);
            
        builder.Property(dt => dt.TrustedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(dt => dt.IsRevoked)
            .HasDefaultValue(false);
            
        builder.Property(dt => dt.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(dt => dt.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(dt => dt.UserId);
        builder.HasIndex(dt => dt.DeviceName);

        // Relationships are already defined in User configuration
    }
}