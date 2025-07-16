using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Contracts.Infrastructure;

namespace Artemis.Auth.Application.Features.Authentication.Commands.Logout;

public class LogoutCommandHandler : IRequestHandler<LogoutCommand, Result<LogoutDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IJwtGenerator _jwtGenerator;
    private readonly ILogger<LogoutCommandHandler> _logger;

    public LogoutCommandHandler(
        IUserRepository userRepository,
        IJwtGenerator jwtGenerator,
        ILogger<LogoutCommandHandler> logger)
    {
        _userRepository = userRepository;
        _jwtGenerator = jwtGenerator;
        _logger = logger;
    }

    public async Task<Result<LogoutDto>> Handle(LogoutCommand request, CancellationToken cancellationToken)
    {
        try
        {
            // Get user to verify it exists
            var user = await _userRepository.GetByIdAsync(request.UserId, cancellationToken);
            if (user == null)
            {
                return Result<LogoutDto>.Failure("User not found");
            }

            // Revoke refresh token(s)
            if (!string.IsNullOrEmpty(request.RefreshToken))
            {
                await _jwtGenerator.RevokeRefreshTokenAsync(request.RefreshToken, request.UserId);
            }

            // If logout all devices, revoke all refresh tokens for user
            if (request.LogoutAllDevices)
            {
                await _jwtGenerator.RevokeAllRefreshTokensAsync(request.UserId);
                
                // Update security stamp to invalidate all existing tokens
                await _userRepository.UpdateSecurityStampAsync(request.UserId, cancellationToken);
            }

            // Add access token to blacklist if provided
            if (!string.IsNullOrEmpty(request.AccessToken))
            {
                await _jwtGenerator.BlacklistTokenAsync(request.AccessToken);
            }

            var result = new LogoutDto
            {
                UserId = request.UserId,
                Message = request.LogoutAllDevices ? 
                    "Successfully logged out from all devices" : 
                    "Successfully logged out",
                LoggedOutAt = DateTime.UtcNow,
                Success = true,
                AllDevicesLoggedOut = request.LogoutAllDevices
            };

            _logger.LogInformation("User logged out successfully: {UserId} (AllDevices: {AllDevices})", 
                request.UserId, request.LogoutAllDevices);

            return Result<LogoutDto>.Success(result, result.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout for user {UserId}", request.UserId);
            return Result<LogoutDto>.Failure("Logout failed. Please try again.");
        }
    }
}