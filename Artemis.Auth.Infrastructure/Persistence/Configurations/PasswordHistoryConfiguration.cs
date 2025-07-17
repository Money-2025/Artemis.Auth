using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class PasswordHistoryConfiguration : BaseEntityConfiguration<PasswordHistory>
{
    public PasswordHistoryConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<PasswordHistory> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("password_history");
        
        builder.Property(ph => ph.UserId)
            .IsRequired();
            
        builder.Property(ph => ph.PasswordHash)
            .IsRequired()
            .HasMaxLength(500);
            
        builder.Property(ph => ph.ChangedAt)
            .HasDefaultValueSql(GetCurrentTimestampSql());
            
        builder.Property(ph => ph.PolicyVersion)
            .HasDefaultValue(1);

        // PasswordHistory-specific indexes
        builder.HasIndex(ph => ph.UserId)
            .HasDatabaseName("ix_password_history_user_id");
        builder.HasIndex(ph => ph.ChangedAt)
            .HasDatabaseName("ix_password_history_changed_at");

        // Relationships are already defined in User configuration
    }
}