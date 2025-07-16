using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Authentication.Commands.VerifyEmail;

public class VerifyEmailCommandHandler : IRequestHandler<VerifyEmailCommand, Result<VerifyEmailDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<VerifyEmailCommandHandler> _logger;

    public VerifyEmailCommandHandler(
        IUserRepository userRepository,
        ILogger<VerifyEmailCommandHandler> logger)
    {
        _userRepository = userRepository;
        _logger = logger;
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

            // Validate verification token (in a real implementation, you'd validate against stored token)
            if (string.IsNullOrEmpty(request.Token) || request.Token.Length < 32)
            {
                return Result<VerifyEmailDto>.Failure("Invalid verification token");
            }

            // Update email confirmation status
            await _userRepository.UpdateEmailConfirmationAsync(user.Id, true, cancellationToken);

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