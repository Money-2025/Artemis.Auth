using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class UserSessionConfiguration : BaseEntityConfiguration<UserSession>
{
    public UserSessionConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<UserSession> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("user_sessions");
        
        builder.Property(us => us.UserId)
            .IsRequired();
            
        builder.Property(us => us.SessionTokenHash)
            .IsRequired()
            .HasMaxLength(500);
            
        builder.Property(us => us.ExpiresAt)
            .IsRequired();
            
        builder.Property(us => us.IpAddress)
            .HasMaxLength(45);
            
        builder.Property(us => us.UserAgent)
            .HasColumnType("text");
            
        builder.Property(us => us.CountryCode)
            .HasMaxLength(2);
            
        builder.Property(us => us.DeviceFingerprint)
            .HasMaxLength(500);
            
        builder.Property(us => us.IsRevoked)
            .HasDefaultValue(false);

        // UserSession-specific indexes
        builder.HasIndex(us => us.SessionTokenHash)
            .IsUnique()
            .HasFilter(GetUniqueFilterSql("is_deleted") + " AND " + QuoteColumn("expires_at") + " >= " + GetCurrentTimestampSql())
            .HasDatabaseName("IX_user_sessions_SessionTokenHash");
            
        builder.HasIndex(us => us.ExpiresAt)
            .HasDatabaseName("IX_user_sessions_ExpiresAt");
        builder.HasIndex(us => us.UserId)
            .HasDatabaseName("IX_user_sessions_UserId");

        // Relationships are already defined in User configuration
    }
}