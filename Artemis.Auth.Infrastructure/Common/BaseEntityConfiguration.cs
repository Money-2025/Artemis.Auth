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
            
        builder.Property<DateTime?>("DeletedAt")
            .IsRequired(false);
            
        builder.Property<Guid?>("DeletedBy")
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
            .HasDatabaseName($"IX_{typeof(TEntity).Name}_IsDeleted");
            
        builder.HasIndex(e => e.CreatedAt)
            .HasDatabaseName($"IX_{typeof(TEntity).Name}_CreatedAt");
    }
    
    protected string GetUniqueFilterSql(string columnName)
    {
        return _databaseProvider.GetBooleanFilterSql(columnName, false);
    }
    
    protected string GetBooleanFilterSql(string columnName, bool value)
    {
        return _databaseProvider.GetBooleanFilterSql(columnName, value);
    }
    
    protected string QuoteColumn(string columnName)
    {
        return _databaseProvider.GetColumnQuote(columnName);
    }
    
    protected string GetCurrentTimestampSql()
    {
        return _databaseProvider.GetCurrentTimestampSql();
    }
}