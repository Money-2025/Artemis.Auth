using System.Security.Claims;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Application.Contracts.Infrastructure;

public interface IJwtGenerator
{
    Task<string> GenerateAccessTokenAsync(User user, IEnumerable<string> roles, IEnumerable<string> permissions);
    Task<string> GenerateTokenAsync(User user, IList<string> roles);
    Task<string> GenerateRefreshTokenAsync(User user);
    Task<string> GenerateRefreshTokenAsync(Guid userId);
    Task<(string Token, DateTime ExpiresAt)> GenerateResetTokenAsync(User user);
    Task<(string Token, DateTime ExpiresAt)> GenerateConfirmationTokenAsync(User user);
    Task<bool> ValidateTokenAsync(string token, string tokenType);
    Task<Guid?> GetUserIdFromTokenAsync(string token);
    Task<Dictionary<string, object>> GetTokenClaimsAsync(string token);
    Task RevokeTokenAsync(string token);
    Task RevokeAllUserTokensAsync(Guid userId);
    Task<bool> IsTokenRevokedAsync(string token);
    Task<bool> ValidateRefreshTokenAsync(string refreshToken, Guid userId);
    Task RevokeRefreshTokenAsync(string refreshToken, Guid userId);
    Task RevokeAllRefreshTokensAsync(Guid userId);
    Task BlacklistTokenAsync(string accessToken);
    Task<TimeSpan> GetTokenRemainingLifetimeAsync(string token);
    Task<(bool IsValid, ClaimsPrincipal? Principal, string? Error)> ValidateAndGetPrincipalAsync(string token, string expectedPurpose);

}