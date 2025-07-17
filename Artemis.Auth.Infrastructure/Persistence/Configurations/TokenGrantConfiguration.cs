using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class TokenGrantConfiguration : BaseEntityConfiguration<TokenGrant>
{
    public TokenGrantConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<TokenGrant> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("token_grants");
        
        builder.Property(tg => tg.UserId)
            .IsRequired();
            
        builder.Property(tg => tg.TokenType)
            .IsRequired()
            .HasConversion(
                v => v.ToString().ToLowerInvariant(),
                v => Enum.Parse<TokenType>(v, true))
            .HasMaxLength(50);
            
        builder.Property(tg => tg.TokenHash)
            .IsRequired()
            .HasMaxLength(500);
            
        builder.Property(tg => tg.ExpiresAt)
            .IsRequired();
            
        builder.Property(tg => tg.IsUsed)
            .HasDefaultValue(false);

        // TokenGrant-specific indexes
        builder.HasIndex(tg => tg.TokenHash)
            .IsUnique()
            .HasFilter(GetUniqueFilterSql("is_deleted"))
            .HasDatabaseName("ix_token_grants_token_hash");
            
        builder.HasIndex(tg => tg.ExpiresAt)
            .HasDatabaseName("ix_token_grants_expires_at");
            
        builder.HasIndex(tg => tg.UserId)
            .HasDatabaseName("ix_token_grants_user_id");
            
        // Composite index for active token lookup
        builder.HasIndex(tg => new { tg.UserId, tg.TokenType, tg.ExpiresAt })
            .HasFilter(GetBooleanFilterSql("is_deleted", false) + " AND " + GetBooleanFilterSql("is_used", false))
            .HasDatabaseName("ix_token_grants_active_lookup");

        // Relationships are already defined in User configuration
    }
}