using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class DeviceTrustConfiguration : BaseEntityConfiguration<DeviceTrust>
{
    public DeviceTrustConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<DeviceTrust> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("device_trusts");
        
        builder.Property(dt => dt.UserId)
            .IsRequired();
            
        builder.Property(dt => dt.DeviceName)
            .HasMaxLength(256);
            
        builder.Property(dt => dt.TrustedAt)
            .HasDefaultValueSql(GetCurrentTimestampSql());
            
        builder.Property(dt => dt.IsRevoked)
            .HasDefaultValue(false);

        // DeviceTrust-specific indexes
        builder.HasIndex(dt => dt.UserId)
            .HasDatabaseName("IX_device_trusts_UserId");
        builder.HasIndex(dt => dt.DeviceName)
            .HasDatabaseName("IX_device_trusts_DeviceName");

        // Relationships are already defined in User configuration
    }
}