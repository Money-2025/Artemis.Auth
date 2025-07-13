using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class PasswordHistoryConfiguration : IEntityTypeConfiguration<PasswordHistory>
{
    public void Configure(EntityTypeBuilder<PasswordHistory> builder)
    {
        builder.ToTable("password_history");
        
        builder.HasKey(ph => ph.Id);
        
        builder.Property(ph => ph.UserId)
            .IsRequired();
            
        builder.Property(ph => ph.PasswordHash)
            .IsRequired()
            .HasMaxLength(500);
            
        builder.Property(ph => ph.ChangedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(ph => ph.PolicyVersion)
            .HasDefaultValue(1);
            
        builder.Property(ph => ph.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(ph => ph.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(ph => ph.UserId);
        builder.HasIndex(ph => ph.ChangedAt);

        // Relationships are already defined in User configuration
    }
}