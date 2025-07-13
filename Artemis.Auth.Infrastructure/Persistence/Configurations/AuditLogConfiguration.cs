using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable("audit_logs");
        
        builder.HasKey(al => al.Id);
        
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
            .HasDefaultValueSql("now()");
            
        builder.Property(al => al.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(al => al.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(al => new { al.TableName, al.Action });
        builder.HasIndex(al => al.PerformedAt);

        // Relationships are already defined in User configuration
    }
}