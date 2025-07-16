using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Services;

/// <summary>
/// Token Blacklist Service: Manages revoked tokens to prevent their reuse
/// Implements in-memory storage with expiration cleanup
/// Used by JWT Service for token revocation and validation
/// Thread-safe implementation for concurrent access
/// </summary>
public class TokenBlacklistService
{
    private readonly ConcurrentDictionary<string, DateTime> _blacklistedTokens;
    private readonly JwtConfiguration _jwtConfig;
    private readonly ILogger<TokenBlacklistService> _logger;
    private readonly Timer? _cleanupTimer;

    /// <summary>
    /// Constructor: Initializes blacklist storage and cleanup timer
    /// Sets up automatic cleanup of expired blacklisted tokens
    /// Uses concurrent dictionary for thread-safe operations
    /// </summary>
    public TokenBlacklistService(
        IOptions<JwtConfiguration> jwtOptions,
        ILogger<TokenBlacklistService> logger)
    {
        _jwtConfig = jwtOptions.Value;
        _logger = logger;
        _blacklistedTokens = new ConcurrentDictionary<string, DateTime>();

        // Setup cleanup timer if blacklisting is enabled
        if (_jwtConfig.EnableTokenBlacklisting)
        {
            var cleanupInterval = TimeSpan.FromMinutes(_jwtConfig.BlacklistCleanupIntervalMinutes);
            _cleanupTimer = new Timer(CleanupExpiredTokens, null, cleanupInterval, cleanupInterval);
            
            _logger.LogInformation("Token blacklist service initialized with cleanup interval: {Interval}", 
                cleanupInterval);
        }
    }

    /// <summary>
    /// Adds a token to the blacklist with its expiration time
    /// Token will be automatically removed after expiration
    /// Thread-safe operation using concurrent dictionary
    /// </summary>
    public Task BlacklistTokenAsync(string token, DateTime expirationTime)
    {
        if (string.IsNullOrEmpty(token))
            throw new ArgumentException("Token cannot be null or empty", nameof(token));

        if (!_jwtConfig.EnableTokenBlacklisting)
        {
            _logger.LogWarning("Token blacklisting is disabled. Token will not be blacklisted.");
            return Task.CompletedTask;
        }

        try
        {
            // Add token to blacklist with its expiration time
            _blacklistedTokens.TryAdd(token, expirationTime);
            
            _logger.LogDebug("Token blacklisted successfully. Current blacklist size: {Size}", 
                _blacklistedTokens.Count);
            
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while blacklisting token");
            throw;
        }
    }

    /// <summary>
    /// Checks if a token is blacklisted
    /// Returns true if token is in blacklist and not expired
    /// Thread-safe operation with automatic cleanup of expired entries
    /// </summary>
    public Task<bool> IsTokenBlacklistedAsync(string token)
    {
        if (string.IsNullOrEmpty(token))
            return Task.FromResult(false);

        if (!_jwtConfig.EnableTokenBlacklisting)
            return Task.FromResult(false);

        try
        {
            // Check if token exists in blacklist
            if (_blacklistedTokens.TryGetValue(token, out var expirationTime))
            {
                // If token has expired, remove it and return false
                if (expirationTime <= DateTime.UtcNow)
                {
                    _blacklistedTokens.TryRemove(token, out _);
                    _logger.LogDebug("Expired blacklisted token removed during lookup");
                    return Task.FromResult(false);
                }

                _logger.LogDebug("Token found in blacklist and still valid");
                return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while checking token blacklist status");
            // In case of error, assume token is not blacklisted to avoid blocking valid requests
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Removes a token from the blacklist
    /// Used for manual token unblocking (rare scenarios)
    /// Thread-safe operation
    /// </summary>
    public Task RemoveTokenFromBlacklistAsync(string token)
    {
        if (string.IsNullOrEmpty(token))
            throw new ArgumentException("Token cannot be null or empty", nameof(token));

        if (!_jwtConfig.EnableTokenBlacklisting)
        {
            _logger.LogWarning("Token blacklisting is disabled. No action taken.");
            return Task.CompletedTask;
        }

        try
        {
            var removed = _blacklistedTokens.TryRemove(token, out _);
            
            if (removed)
            {
                _logger.LogDebug("Token removed from blacklist successfully");
            }
            else
            {
                _logger.LogDebug("Token was not found in blacklist");
            }
            
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while removing token from blacklist");
            throw;
        }
    }

    /// <summary>
    /// Blacklists all tokens for a specific user
    /// Used when user changes password or account is compromised
    /// Requires token-to-user mapping (implemented in JWT Service)
    /// </summary>
    public Task BlacklistAllUserTokensAsync(Guid userId, DateTime beforeTime)
    {
        if (!_jwtConfig.EnableTokenBlacklisting)
        {
            _logger.LogWarning("Token blacklisting is disabled. User tokens will not be blacklisted.");
            return Task.CompletedTask;
        }

        try
        {
            // Note: This is a simplified implementation
            // In a production system, you'd want to store user-to-token mappings
            // and iterate through user's tokens to blacklist them
            
            _logger.LogInformation("Blacklisting all tokens for user {UserId} before {Time}", 
                userId, beforeTime);
            
            // For now, we'll add a user-specific entry
            // JWT Service should check this when validating tokens
            var userTokenKey = $"user:{userId}:before:{beforeTime:yyyy-MM-ddTHH:mm:ssZ}";
            _blacklistedTokens.TryAdd(userTokenKey, beforeTime.Add(TimeSpan.FromDays(30))); // Keep for 30 days
            
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while blacklisting all user tokens for user {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// Checks if all tokens for a user are blacklisted before a specific time
    /// Used in conjunction with BlacklistAllUserTokensAsync
    /// </summary>
    public Task<bool> AreUserTokensBlacklistedAsync(Guid userId, DateTime tokenIssuedAt)
    {
        if (!_jwtConfig.EnableTokenBlacklisting)
            return Task.FromResult(false);

        try
        {
            // Check if there's a user-specific blacklist entry
            var userTokenKeys = _blacklistedTokens.Keys
                .Where(k => k.StartsWith($"user:{userId}:before:"))
                .ToList();

            foreach (var key in userTokenKeys)
            {
                if (_blacklistedTokens.TryGetValue(key, out var blacklistExpiration))
                {
                    // Extract the blacklist time from the key
                    var beforeTimeStr = key.Split(':')[3];
                    if (DateTime.TryParse(beforeTimeStr, out var beforeTime))
                    {
                        // If token was issued before the blacklist time, it's blacklisted
                        if (tokenIssuedAt < beforeTime && blacklistExpiration > DateTime.UtcNow)
                        {
                            return Task.FromResult(true);
                        }
                    }
                }
            }

            return Task.FromResult(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while checking user token blacklist status for user {UserId}", userId);
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Gets current blacklist statistics
    /// Used for monitoring and debugging
    /// </summary>
    public Task<(int TotalTokens, int ExpiredTokens)> GetBlacklistStatsAsync()
    {
        if (!_jwtConfig.EnableTokenBlacklisting)
            return Task.FromResult((0, 0));

        try
        {
            var now = DateTime.UtcNow;
            var totalTokens = _blacklistedTokens.Count;
            var expiredTokens = _blacklistedTokens.Count(kvp => kvp.Value <= now);

            return Task.FromResult((totalTokens, expiredTokens));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while getting blacklist statistics");
            return Task.FromResult((0, 0));
        }
    }

    /// <summary>
    /// Manual cleanup of expired tokens
    /// Called by timer automatically, but can be called manually for immediate cleanup
    /// Thread-safe operation
    /// </summary>
    public Task CleanupExpiredTokensAsync()
    {
        if (!_jwtConfig.EnableTokenBlacklisting)
            return Task.CompletedTask;

        CleanupExpiredTokens(null);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Internal cleanup method called by timer
    /// Removes expired tokens from blacklist to prevent memory leaks
    /// Logs cleanup statistics for monitoring
    /// </summary>
    private void CleanupExpiredTokens(object? state)
    {
        if (!_jwtConfig.EnableTokenBlacklisting)
            return;

        try
        {
            var now = DateTime.UtcNow;
            var initialCount = _blacklistedTokens.Count;
            var removedCount = 0;

            // Find and remove expired tokens
            var expiredTokens = _blacklistedTokens
                .Where(kvp => kvp.Value <= now)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var token in expiredTokens)
            {
                if (_blacklistedTokens.TryRemove(token, out _))
                {
                    removedCount++;
                }
            }

            if (removedCount > 0)
            {
                _logger.LogInformation("Blacklist cleanup completed. Removed {RemovedCount} expired tokens. " +
                    "Remaining: {RemainingCount}", removedCount, _blacklistedTokens.Count);
            }
            else
            {
                _logger.LogDebug("Blacklist cleanup completed. No expired tokens found. " +
                    "Total tokens: {TotalCount}", initialCount);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred during blacklist cleanup");
        }
    }

    /// <summary>
    /// Disposes resources and stops cleanup timer
    /// Called during application shutdown
    /// </summary>
    public void Dispose()
    {
        try
        {
            _cleanupTimer?.Dispose();
            _blacklistedTokens.Clear();
            _logger.LogInformation("Token blacklist service disposed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while disposing token blacklist service");
        }
    }
}