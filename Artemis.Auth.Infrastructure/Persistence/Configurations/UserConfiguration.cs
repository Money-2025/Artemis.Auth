using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");
        
        builder.HasKey(u => u.Id);
        
        builder.Property(u => u.Username)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(u => u.NormalizedUsername)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(u => u.Email)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(u => u.NormalizedEmail)
            .IsRequired()
            .HasMaxLength(256);
            
        builder.Property(u => u.EmailConfirmed)
            .HasDefaultValue(false);
            
        builder.Property(u => u.PhoneNumber)
            .HasMaxLength(50);
            
        builder.Property(u => u.PhoneNumberConfirmed)
            .HasDefaultValue(false);
            
        builder.Property(u => u.PasswordHash)
            .IsRequired()
            .HasMaxLength(500);
            
        builder.Property(u => u.SecurityStamp)
            .HasMaxLength(256);
            
        builder.Property(u => u.TwoFactorEnabled)
            .HasDefaultValue(false);
            
        builder.Property(u => u.IsDeleted)
            .HasDefaultValue(false);
            
        builder.Property(u => u.FailedLoginCount)
            .HasDefaultValue(0);
            
        builder.Property(u => u.CreatedAt)
            .HasDefaultValueSql("now()");
            
        builder.Property(u => u.RowVersion)
            .IsRequired()
            .HasDefaultValue(1);

        // Indexes
        builder.HasIndex(u => u.NormalizedUsername)
            .IsUnique()
            .HasFilter("\"is_deleted\" = false");
            
        builder.HasIndex(u => u.NormalizedEmail)
            .IsUnique()
            .HasFilter("\"is_deleted\" = false");
            
        builder.HasIndex(u => u.PhoneNumber)
            .IsUnique()
            .HasFilter("\"phone_number_confirmed\" = true AND \"is_deleted\" = false");
            
        builder.HasIndex(u => u.IsDeleted);

        // Relationships
        builder.HasMany(u => u.UserRoles)
            .WithOne(ur => ur.User)
            .HasForeignKey(ur => ur.UserId)
            .OnDelete(DeleteBehavior.Cascade);
            
        builder.HasMany(u => u.UserMfaMethods)
            .WithOne(umfa => umfa.User)
            .HasForeignKey(umfa => umfa.UserId)
            .OnDelete(DeleteBehavior.Cascade);
            
        builder.HasMany(u => u.TokenGrants)
            .WithOne(tg => tg.User)
            .HasForeignKey(tg => tg.UserId)
            .OnDelete(DeleteBehavior.Cascade);
            
        builder.HasMany(u => u.AuditLogs)
            .WithOne(al => al.User)
            .HasForeignKey(al => al.PerformedBy)
            .OnDelete(DeleteBehavior.SetNull);
            
        builder.HasMany(u => u.UserSessions)
            .WithOne(us => us.User)
            .HasForeignKey(us => us.UserId)
            .OnDelete(DeleteBehavior.Cascade);
            
        builder.HasMany(u => u.PasswordHistories)
            .WithOne(ph => ph.User)
            .HasForeignKey(ph => ph.UserId)
            .OnDelete(DeleteBehavior.Cascade);
            
        builder.HasMany(u => u.DeviceTrusts)
            .WithOne(dt => dt.User)
            .HasForeignKey(dt => dt.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}