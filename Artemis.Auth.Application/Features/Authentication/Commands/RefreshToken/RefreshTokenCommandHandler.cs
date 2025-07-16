using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Contracts.Infrastructure;
using System.Security.Claims;

namespace Artemis.Auth.Application.Features.Authentication.Commands.RefreshToken;

public class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, Result<RefreshTokenDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IJwtGenerator _jwtGenerator;
    private readonly ILogger<RefreshTokenCommandHandler> _logger;

    public RefreshTokenCommandHandler(
        IUserRepository userRepository,
        IJwtGenerator jwtGenerator,
        ILogger<RefreshTokenCommandHandler> logger)
    {
        _userRepository = userRepository;
        _jwtGenerator = jwtGenerator;
        _logger = logger;
    }

    public async Task<Result<RefreshTokenDto>> Handle(RefreshTokenCommand request, CancellationToken cancellationToken)
    {
        try
        {
            // Get user ID from JWT token (simplified approach)
            var userId = await _jwtGenerator.GetUserIdFromTokenAsync(request.AccessToken);
            if (userId == null)
            {
                return Result<RefreshTokenDto>.Failure("Invalid access token");
            }

            // Get user from database
            var user = await _userRepository.GetByIdAsync(userId.Value, cancellationToken);
            if (user == null)
            {
                return Result<RefreshTokenDto>.Failure("User not found");
            }

            // Check if user is locked out
            if (user.IsLockedOut())
            {
                return Result<RefreshTokenDto>.Failure("Account is locked");
            }

            // Validate refresh token
            var refreshTokenValid = await _jwtGenerator.ValidateRefreshTokenAsync(request.RefreshToken, userId.Value);
            if (!refreshTokenValid)
            {
                return Result<RefreshTokenDto>.Failure("Invalid or expired refresh token");
            }

            // Get user roles
            var userRoles = await _userRepository.GetUserRolesAsync(userId.Value, cancellationToken);

            // Generate new tokens
            var newAccessToken = await _jwtGenerator.GenerateTokenAsync(user, userRoles.ToList());
            var newRefreshToken = await _jwtGenerator.GenerateRefreshTokenAsync(userId.Value);

            // Update last login
            await _userRepository.UpdateLastLoginAsync(userId.Value, DateTime.UtcNow, request.IpAddress ?? "Unknown", cancellationToken);

            var result = new RefreshTokenDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15), // Typically 15 minutes
                RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7), // Typically 7 days
                TokenType = "Bearer",
                UserId = user.Id,
                Username = user.Username
            };

            _logger.LogInformation("Token refreshed successfully for user: {Username} ({UserId})", user.Username, user.Id);

            return Result<RefreshTokenDto>.Success(result, "Token refreshed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token refresh");
            return Result<RefreshTokenDto>.Failure("Token refresh failed. Please login again.");
        }
    }
}