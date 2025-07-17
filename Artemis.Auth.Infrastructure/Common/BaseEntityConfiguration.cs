using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Common;

namespace Artemis.Auth.Infrastructure.Common;

public abstract class BaseEntityConfiguration<TEntity> : IEntityTypeConfiguration<TEntity>
    where TEntity : AuditableEntity
{
    protected readonly DatabaseProvider _databaseProvider;
    
    protected BaseEntityConfiguration(DatabaseConfiguration databaseConfiguration)
    {
        _databaseProvider = databaseConfiguration.Provider;
    }
    
    public virtual void Configure(EntityTypeBuilder<TEntity> builder)
    {
        // Configure primary key
        builder.HasKey(e => e.Id);
        
        // Configure audit fields with proper defaults
        builder.Property(e => e.IsDeleted)
            .HasDefaultValue(false)
            .IsRequired();
            
        builder.Property(e => e.DeletedAt)
            .IsRequired(false);

        builder.Property(e => e.DeletedBy)
            .IsRequired(false);

            
        builder.Property(e => e.CreatedAt)
            .HasDefaultValueSql(_databaseProvider.GetCurrentTimestampSql())
            .IsRequired();
            
        builder.Property(e => e.RowVersion)
            .HasDefaultValue(1)
            .IsRequired();
            
        // Configure optional audit fields
        builder.Property(e => e.CreatedBy)
            .IsRequired(false);
            
        builder.Property(e => e.ModifiedAt)
            .IsRequired(false);
            
        builder.Property(e => e.ModifiedBy)
            .IsRequired(false);
            
        // Add soft delete filter
        builder.HasQueryFilter(e => !e.IsDeleted);
        
        // Add standard indexes for performance
        builder.HasIndex(e => e.IsDeleted)
            .HasDatabaseName($"ix_{typeof(TEntity).Name.ToLowerInvariant()}_is_deleted");
            
        builder.HasIndex(e => e.CreatedAt)
            .HasDatabaseName($"ix_{typeof(TEntity).Name.ToLowerInvariant()}_created_at");
    }
    
    /// <summary>
    /// Gets SQL filter for non-deleted records using snake_case column naming
    /// </summary>
    protected string GetUniqueFilterSql(string snakeCaseColumnName)
    {
        return _databaseProvider.GetBooleanFilterSql(snakeCaseColumnName, false);
    }
    
    /// <summary>
    /// Gets SQL filter for boolean columns using snake_case column naming
    /// </summary>
    protected string GetBooleanFilterSql(string snakeCaseColumnName, bool value)
    {
        return _databaseProvider.GetBooleanFilterSql(snakeCaseColumnName, value);
    }
    
    /// <summary>
    /// Quotes column name according to database provider conventions
    /// </summary>
    protected string QuoteColumn(string snakeCaseColumnName)
    {
        return _databaseProvider.GetColumnQuote(snakeCaseColumnName);
    }
    
    /// <summary>
    /// Gets current timestamp SQL expression for the database provider
    /// </summary>
    protected string GetCurrentTimestampSql()
    {
        return _databaseProvider.GetCurrentTimestampSql();
    }
    
    /// <summary>
    /// Converts PascalCase property name to snake_case column name
    /// </summary>
    protected string ToSnakeCase(string pascalCase)
    {
        return string.Concat(pascalCase.Select((x, i) => i > 0 && char.IsUpper(x) ? "_" + x : x.ToString())).ToLower();
    }
}