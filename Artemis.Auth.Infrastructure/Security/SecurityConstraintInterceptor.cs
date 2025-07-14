using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Common;

namespace Artemis.Auth.Infrastructure.Security;

public class SecurityConstraintInterceptor : SaveChangesInterceptor
{
    private readonly ILogger<SecurityConstraintInterceptor> _logger;
    
    public SecurityConstraintInterceptor(ILogger<SecurityConstraintInterceptor> logger)
    {
        _logger = logger;
    }
    
    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        if (eventData.Context == null)
            return await base.SavingChangesAsync(eventData, result, cancellationToken);
        
        var validationErrors = new List<ValidationError>();
        
        foreach (var entry in eventData.Context.ChangeTracker.Entries())
        {
            if (entry.Entity is IValidatable validatable && 
                (entry.State == EntityState.Added || entry.State == EntityState.Modified))
            {
                var validationResult = validatable.Validate();
                if (!validationResult.IsValid)
                {
                    validationErrors.AddRange(validationResult.Errors);
                }
            }
            
            // Security-specific constraints
            if (entry.Entity is User user)
            {
                ValidateUserConstraints(user, validationErrors);
            }
            else if (entry.Entity is TokenGrant token)
            {
                ValidateTokenConstraints(token, validationErrors);
            }
            else if (entry.Entity is UserSession session)
            {
                ValidateSessionConstraints(session, validationErrors);
            }
        }
        
        if (validationErrors.Any())
        {
            var errorMessage = string.Join("; ", validationErrors.Select(e => $"{e.Property}: {e.Message}"));
            _logger.LogWarning("Validation failed during save: {ValidationErrors}", errorMessage);
            throw new ValidationException(validationErrors);
        }
        
        return await base.SavingChangesAsync(eventData, result, cancellationToken);
    }
    
    private void ValidateUserConstraints(User user, List<ValidationError> errors)
    {
        // Ensure normalized fields are properly set
        if (string.IsNullOrWhiteSpace(user.NormalizedUsername))
        {
            user.NormalizedUsername = user.Username.ToUpperInvariant();
        }
        
        if (string.IsNullOrWhiteSpace(user.NormalizedEmail))
        {
            user.NormalizedEmail = user.Email.ToUpperInvariant();
        }
        
        // Security stamp validation
        if (string.IsNullOrWhiteSpace(user.SecurityStamp))
        {
            user.SecurityStamp = Guid.NewGuid().ToString();
        }
        
        // Lockout validation
        if (user.LockoutEnd.HasValue && user.LockoutEnd.Value <= DateTime.UtcNow)
        {
            user.LockoutEnd = null;
            user.FailedLoginCount = 0;
        }
        
        // Failed login count bounds
        if (user.FailedLoginCount < 0)
        {
            user.FailedLoginCount = 0;
        }
        else if (user.FailedLoginCount > 10)
        {
            user.FailedLoginCount = 10;
        }
    }
    
    private void ValidateTokenConstraints(TokenGrant token, List<ValidationError> errors)
    {
        // Token must not be expired when created
        if (token.ExpiresAt <= DateTime.UtcNow)
        {
            errors.Add(new ValidationError(nameof(TokenGrant.ExpiresAt), "Token cannot be expired when created"));
        }
        
        // Token hash must be provided
        if (string.IsNullOrWhiteSpace(token.TokenHash))
        {
            errors.Add(new ValidationError(nameof(TokenGrant.TokenHash), "Token hash is required"));
        }
        
        // Token hash minimum length for security
        if (token.TokenHash.Length < 32)
        {
            errors.Add(new ValidationError(nameof(TokenGrant.TokenHash), "Token hash must be at least 32 characters"));
        }
    }
    
    private void ValidateSessionConstraints(UserSession session, List<ValidationError> errors)
    {
        // Session must not be expired when created
        if (session.ExpiresAt <= DateTime.UtcNow)
        {
            errors.Add(new ValidationError(nameof(UserSession.ExpiresAt), "Session cannot be expired when created"));
        }
        
        // Session token must be provided
        if (string.IsNullOrWhiteSpace(session.SessionTokenHash))
        {
            errors.Add(new ValidationError(nameof(UserSession.SessionTokenHash), "Session token is required"));
        }
        
        // IP address validation
        if (string.IsNullOrWhiteSpace(session.IpAddress))
        {
            errors.Add(new ValidationError(nameof(UserSession.IpAddress), "IP address is required"));
        }
    }
}

public class ValidationException : Exception
{
    public List<ValidationError> ValidationErrors { get; }
    
    public ValidationException(List<ValidationError> validationErrors)
        : base($"Validation failed: {string.Join("; ", validationErrors.Select(e => $"{e.Property}: {e.Message}"))}")
    {
        ValidationErrors = validationErrors;
    }
}