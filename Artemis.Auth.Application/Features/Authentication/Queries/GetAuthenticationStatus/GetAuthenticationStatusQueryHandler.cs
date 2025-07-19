using MediatR;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Authentication.Queries.GetAuthenticationStatus;

public class GetAuthenticationStatusQueryHandler : IRequestHandler<GetAuthenticationStatusQuery, Result<AuthenticationStatusDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IMapper _mapper;
    private readonly ILogger<GetAuthenticationStatusQueryHandler> _logger;

    public GetAuthenticationStatusQueryHandler(
        IUserRepository userRepository,
        IMapper mapper,
        ILogger<GetAuthenticationStatusQueryHandler> logger)
    {
        _userRepository = userRepository;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<Result<AuthenticationStatusDto>> Handle(GetAuthenticationStatusQuery request, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Getting authentication status for user: {UserId}", request.UserId);

            var user = await _userRepository.GetByIdAsync(request.UserId, cancellationToken);
            if (user == null || user.IsDeleted)
            {
                _logger.LogWarning("User not found: {UserId}", request.UserId);
                return Result<AuthenticationStatusDto>.Failure("User not found");
            }

            var result = new AuthenticationStatusDto
            {
                UserId = user.Id,
                Username = user.Username,
                Email = user.Email,
                IsAuthenticated = true, // If we're checking status, user is authenticated
                IsEmailConfirmed = user.EmailConfirmed,
                IsPhoneNumberConfirmed = user.PhoneNumberConfirmed,
                IsTwoFactorEnabled = user.TwoFactorEnabled,
                IsLockedOut = user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow,
                LockoutEnd = user.LockoutEnd,
                FailedLoginCount = user.FailedLoginCount,
                LastLoginAt = user.LastLoginAt ?? user.CreatedAt,
                Roles = new List<string>(), // TODO: Get user roles
                Permissions = new List<string>(), // TODO: Get user permissions
                ActiveSessions = new List<string>() // TODO: Get active sessions
            };

            _logger.LogInformation("Authentication status retrieved for user: {UserId}", request.UserId);

            return Result<AuthenticationStatusDto>.Success(result, "Authentication status retrieved successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting authentication status for user: {UserId}", request.UserId);
            return Result<AuthenticationStatusDto>.Failure("Failed to get authentication status");
        }
    }
}