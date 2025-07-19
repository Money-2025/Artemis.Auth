using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Authentication.Queries.ValidateToken;

public class ValidateTokenQueryHandler : IRequestHandler<ValidateTokenQuery, Result<ValidateTokenDto>>
{
    private readonly IJwtGenerator _jwtGenerator;
    private readonly IUserRepository _userRepository;
    private readonly ILogger<ValidateTokenQueryHandler> _logger;

    public ValidateTokenQueryHandler(
        IJwtGenerator jwtGenerator,
        IUserRepository userRepository,
        ILogger<ValidateTokenQueryHandler> logger)
    {
        _jwtGenerator = jwtGenerator;
        _userRepository = userRepository;
        _logger = logger;
    }

    public async Task<Result<ValidateTokenDto>> Handle(ValidateTokenQuery request, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Validating token from IP: {IpAddress}", request.IpAddress);

            // Check if token is blacklisted/revoked
            var isRevoked = await _jwtGenerator.IsTokenRevokedAsync(request.Token);
            if (isRevoked)
            {
                _logger.LogWarning("Token validation failed - token is revoked");
                return Result<ValidateTokenDto>.Success(new ValidateTokenDto { IsValid = false }, "Token is revoked");
            }

            // Validate token structure and signature
            var isValid = await _jwtGenerator.ValidateTokenAsync(request.Token, request.TokenType ?? "access");
            if (!isValid)
            {
                _logger.LogWarning("Token validation failed - invalid token structure or signature");
                return Result<ValidateTokenDto>.Success(new ValidateTokenDto { IsValid = false }, "Invalid token");
            }

            // Get user information from token
            var userId = await _jwtGenerator.GetUserIdFromTokenAsync(request.Token);
            if (userId == null)
            {
                _logger.LogWarning("Token validation failed - could not extract user ID");
                return Result<ValidateTokenDto>.Success(new ValidateTokenDto { IsValid = false }, "Invalid token claims");
            }

            // Get user from database to verify they still exist and are active
            var user = await _userRepository.GetByIdAsync(userId.Value, cancellationToken);
            if (user == null || user.IsDeleted)
            {
                _logger.LogWarning("Token validation failed - user not found or deleted: {UserId}", userId.Value);
                return Result<ValidateTokenDto>.Success(new ValidateTokenDto { IsValid = false }, "User not found");
            }

            // Get token claims and remaining lifetime
            var claims = await _jwtGenerator.GetTokenClaimsAsync(request.Token);
            var remainingLifetime = await _jwtGenerator.GetTokenRemainingLifetimeAsync(request.Token);

            var result = new ValidateTokenDto
            {
                IsValid = true,
                UserId = userId.Value,
                Username = user.Username,
                Roles = new List<string>(), // TODO: Get user roles from database
                Permissions = new List<string>(), // TODO: Get user permissions from database
                ExpiresAt = DateTime.UtcNow.Add(remainingLifetime),
                RemainingLifetime = remainingLifetime,
                Claims = claims
            };

            _logger.LogInformation("Token validation successful for user: {UserId}", userId.Value);

            return Result<ValidateTokenDto>.Success(result, "Token is valid");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token validation");
            return Result<ValidateTokenDto>.Failure("Token validation failed");
        }
    }
}