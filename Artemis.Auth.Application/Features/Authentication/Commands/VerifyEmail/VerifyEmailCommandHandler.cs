using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Contracts.Infrastructure;

namespace Artemis.Auth.Application.Features.Authentication.Commands.VerifyEmail;

public class VerifyEmailCommandHandler : IRequestHandler<VerifyEmailCommand, Result<VerifyEmailDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<VerifyEmailCommandHandler> _logger;
    private readonly IJwtGenerator _jwtGenerator;

    public VerifyEmailCommandHandler(
        IUserRepository userRepository,
        ILogger<VerifyEmailCommandHandler> logger,
        IJwtGenerator jwtGenerator)
    {
        _userRepository = userRepository;
        _logger = logger;
        _jwtGenerator = jwtGenerator;
    }

    public async Task<Result<VerifyEmailDto>> Handle(VerifyEmailCommand request, CancellationToken cancellationToken)
    {
        try
        {
            // Get user by email
            var user = await _userRepository.GetByEmailAsync(request.Email, cancellationToken);
            if (user == null)
            {
                return Result<VerifyEmailDto>.Failure("Invalid verification token or email");
            }

            // Check if email is already verified
            if (user.EmailConfirmed)
            {
                var alreadyVerifiedResult = new VerifyEmailDto
                {
                    Email = request.Email,
                    Message = "Email address is already verified",
                    VerifiedAt = DateTime.UtcNow,
                    Success = true,
                    AccountActivated = true
                };

                return Result<VerifyEmailDto>.Success(alreadyVerifiedResult, "Email already verified");
            }

            // Validate JWT confirmation token
            try
            {
                var isTokenValid = await _jwtGenerator.ValidateTokenAsync(request.Token, "confirmation");
                if (!isTokenValid)
                {
                    _logger.LogWarning("Invalid confirmation token for user: {Email}", request.Email);
                    return Result<VerifyEmailDto>.Failure("Invalid or expired verification token");
                }

                // Verify the token belongs to this user
                var tokenUserId = await _jwtGenerator.GetUserIdFromTokenAsync(request.Token);
                if (tokenUserId != user.Id)
                {
                    _logger.LogWarning("Token user ID mismatch for email: {Email}", request.Email);
                    return Result<VerifyEmailDto>.Failure("Invalid verification token");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating confirmation token for user: {Email}", request.Email);
                return Result<VerifyEmailDto>.Failure("Invalid verification token");
            }

            // Update email confirmation status and regenerate security stamp to invalidate existing tokens
            await _userRepository.UpdateEmailConfirmationAsync(user.Id, true, cancellationToken);
            
            // Regenerate security stamp to invalidate all existing tokens for this user
            await _userRepository.UpdateSecurityStampAsync(user.Id, cancellationToken);
            
            _logger.LogInformation("Email verified and security stamp updated for user: {Email}", request.Email);

            var result = new VerifyEmailDto
            {
                Email = request.Email,
                Message = "Email address has been verified successfully. Your account is now active.",
                VerifiedAt = DateTime.UtcNow,
                Success = true,
                AccountActivated = true
            };

            _logger.LogInformation("Email verified successfully for user: {Email}", request.Email);

            return Result<VerifyEmailDto>.Success(result, "Email verified successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during email verification for {Email}", request.Email);
            return Result<VerifyEmailDto>.Failure("Email verification failed. Please try again.");
        }
    }
}