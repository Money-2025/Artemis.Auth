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
            .HasConversion<string>();
            
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
            .HasFilter(GetUniqueFilterSql("is_deleted") + " AND " + QuoteColumn("expires_at") + " >= " + GetCurrentTimestampSql())
            .HasDatabaseName("IX_token_grants_TokenHash");
            
        builder.HasIndex(tg => tg.ExpiresAt)
            .HasDatabaseName("IX_token_grants_ExpiresAt");
        builder.HasIndex(tg => tg.UserId)
            .HasDatabaseName("IX_token_grants_UserId");

        // Relationships are already defined in User configuration
    }
}