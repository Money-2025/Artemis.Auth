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
            .HasFilter(GetUniqueFilterSql("is_deleted"))
            .HasDatabaseName("ix_user_sessions_session_token_hash");
            
        builder.HasIndex(us => us.ExpiresAt)
            .HasDatabaseName("ix_user_sessions_expires_at");
        builder.HasIndex(us => us.UserId)
            .HasDatabaseName("ix_user_sessions_user_id");
            
        // Composite index for active session lookup
        builder.HasIndex(us => new { us.UserId, us.ExpiresAt })
            .HasFilter(GetBooleanFilterSql("is_deleted", false) + " AND " + GetBooleanFilterSql("is_revoked", false))
            .HasDatabaseName("ix_user_sessions_active_lookup");

        // Relationships are already defined in User configuration
    }
}