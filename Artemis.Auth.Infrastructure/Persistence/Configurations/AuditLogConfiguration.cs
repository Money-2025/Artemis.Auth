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
            .HasConversion<string>();
            
        builder.Property(al => al.OldData)
            .HasColumnType("jsonb");
            
        builder.Property(al => al.NewData)
            .HasColumnType("jsonb");
            
        builder.Property(al => al.PerformedAt)
            .HasDefaultValueSql(GetCurrentTimestampSql());

        // AuditLog-specific indexes
        builder.HasIndex(al => new { al.TableName, al.Action })
            .HasDatabaseName("IX_audit_logs_TableName_Action");
        builder.HasIndex(al => al.PerformedAt)
            .HasDatabaseName("IX_audit_logs_PerformedAt");

        // Relationships are already defined in User configuration
    }
}