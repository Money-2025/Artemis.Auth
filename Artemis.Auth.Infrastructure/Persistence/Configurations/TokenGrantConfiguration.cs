using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class TokenGrantConfiguration : IEntityTypeConfiguration<TokenGrant>
{
    public void Configure(EntityTypeBuilder<TokenGrant> builder)
    {
        builder.ToTable("token_grants");
        
        builder.HasKey(tg => tg.Id);
        
        builder.Property(tg => tg.UserId)
            .IsRequired();
            
        builder.Property(tg => tg.TokenType)
            .IsRequired()
            .HasConversion<string>();
            
        builder.Property(tg => tg.TokenHash)
            .IsRequired()
            .HasMaxLength(500);
            
        builder.Property(tg => tg.ExpiresAt)
            .IsRequired();
            
        builder.Property(tg => tg.IsUsed)
            .HasDefaultValue(false);
            
        builder.Property(tg => tg.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(tg => tg.CreatedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(tg => tg.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(tg => tg.TokenHash)
            .IsUnique()
            .HasFilter("\"is_deleted\" = false AND \"expires_at\" >= now()");
            
        builder.HasIndex(tg => tg.ExpiresAt);
        builder.HasIndex(tg => tg.UserId);

        // Relationships are already defined in User configuration
    }
}