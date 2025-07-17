using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Common;
using Artemis.Auth.Infrastructure.Performance;

namespace Artemis.Auth.Infrastructure.Persistence.Configurations;

public class UserConfiguration : BaseEntityConfiguration<User>
{
    public UserConfiguration(DatabaseConfiguration databaseConfiguration) : base(databaseConfiguration)
    {
    }
    
    public override void Configure(EntityTypeBuilder<User> builder)
    {
        // Apply base configuration first
        base.Configure(builder);
        
        builder.ToTable("users");
        
        // User-specific properties
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
            
        builder.Property(u => u.FailedLoginCount)
            .HasDefaultValue(0);

        // User-specific indexes
        builder.HasIndex(u => u.NormalizedUsername)
            .IsUnique()
            .HasFilter(GetUniqueFilterSql("is_deleted"))
            .HasDatabaseName("ix_users_normalized_username");
            
        builder.HasIndex(u => u.NormalizedEmail)
            .IsUnique()
            .HasFilter(GetUniqueFilterSql("is_deleted"))
            .HasDatabaseName("ix_users_normalized_email");
            
        builder.HasIndex(u => u.PhoneNumber)
            .IsUnique()
            .HasFilter(GetBooleanFilterSql("phone_number_confirmed", true) + " AND " + GetBooleanFilterSql("is_deleted", false))
            .HasDatabaseName("ix_users_phone_number");
            
        builder.HasIndex(u => u.LastLoginAt)
            .HasDatabaseName("ix_users_last_login_at");
            
        builder.HasIndex(u => u.LockoutEnd)
            .HasDatabaseName("ix_users_lockout_end");

        // Note: Advanced performance optimizations can be added later after basic migration works
        // builder.AddOptimizedIndexes(_databaseProvider);
        // builder.AddCompositeIndexes(_databaseProvider);
        // builder.AddCoveringIndexes(_databaseProvider);

        // Relationships with optimized delete behavior
        builder.HasMany(u => u.UserRoles)
            .WithOne(ur => ur.User)
            .HasForeignKey(ur => ur.UserId)
            .OnDelete(DeleteBehaviorStrategy.Junction);
            
        builder.HasMany(u => u.UserMfaMethods)
            .WithOne(umfa => umfa.User)
            .HasForeignKey(umfa => umfa.UserId)
            .OnDelete(DeleteBehaviorStrategy.SecuritySensitive);
            
        builder.HasMany(u => u.TokenGrants)
            .WithOne(tg => tg.User)
            .HasForeignKey(tg => tg.UserId)
            .OnDelete(DeleteBehaviorStrategy.SecuritySensitive);
            
        builder.HasMany(u => u.AuditLogs)
            .WithOne(al => al.User)
            .HasForeignKey(al => al.PerformedBy)
            .OnDelete(DeleteBehaviorStrategy.AuditData);
            
        builder.HasMany(u => u.UserSessions)
            .WithOne(us => us.User)
            .HasForeignKey(us => us.UserId)
            .OnDelete(DeleteBehaviorStrategy.SessionData);
            
        builder.HasMany(u => u.PasswordHistories)
            .WithOne(ph => ph.User)
            .HasForeignKey(ph => ph.UserId)
            .OnDelete(DeleteBehaviorStrategy.AuditData);
            
        builder.HasMany(u => u.DeviceTrusts)
            .WithOne(dt => dt.User)
            .HasForeignKey(dt => dt.UserId)
            .OnDelete(DeleteBehaviorStrategy.SecuritySensitive);
    }
}