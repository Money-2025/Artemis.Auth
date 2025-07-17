using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class AuditLogConfiguration : BaseEntityConfiguration<AuditLog>
{
    public AuditLogConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("audit_logs");
        
        builder.Property(al => al.TableName)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(al => al.RecordId)
            .IsRequired();
            
        builder.Property(al => al.Action)
            .IsRequired()
            .HasConversion(
                v => v.ToString().ToLowerInvariant(),
                v => Enum.Parse<AuditAction>(v, true))
            .HasMaxLength(50);
            
        // Use PostgreSQL-specific JSON type only for PostgreSQL provider
        if (_databaseProvider == DatabaseProvider.PostgreSQL)
        {
            builder.Property(al => al.OldData)
                .HasColumnType("jsonb");
                
            builder.Property(al => al.NewData)
                .HasColumnType("jsonb");
        }
        else
        {
            builder.Property(al => al.OldData)
                .HasColumnType("nvarchar(max)");
                
            builder.Property(al => al.NewData)
                .HasColumnType("nvarchar(max)");
        }
            
        builder.Property(al => al.PerformedAt)
            .HasDefaultValueSql(GetCurrentTimestampSql());

        // AuditLog-specific indexes
        builder.HasIndex(al => new { al.TableName, al.Action })
            .HasDatabaseName("ix_audit_logs_table_name_action");
        builder.HasIndex(al => al.PerformedAt)
            .HasDatabaseName("ix_audit_logs_performed_at");
        builder.HasIndex(al => al.RecordId)
            .HasDatabaseName("ix_audit_logs_record_id");

        // Relationships are already defined in User configuration
    }
}