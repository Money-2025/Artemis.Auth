using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        builder.ToTable("user_sessions");
        
        builder.HasKey(us => us.Id);
        
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
            
        builder.Property(us => us.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(us => us.CreatedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(us => us.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(us => us.SessionTokenHash)
            .IsUnique()
            .HasFilter("\"is_deleted\" = false AND \"expires_at\" >= now()");
            
        builder.HasIndex(us => us.ExpiresAt);
        builder.HasIndex(us => us.UserId);

        // Relationships are already defined in User configuration
    }
}