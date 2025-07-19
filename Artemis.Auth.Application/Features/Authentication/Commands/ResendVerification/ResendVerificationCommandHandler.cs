using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Contracts.Infrastructure;

namespace Artemis.Auth.Application.Features.Authentication.Commands.ResendVerification;

public class ResendVerificationCommandHandler : IRequestHandler<ResendVerificationCommand, Result<bool>>
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<ResendVerificationCommandHandler> _logger;
    private readonly IEmailSender _emailSender;
    private readonly IJwtGenerator _jwtGenerator;
    public ResendVerificationCommandHandler(
        IUserRepository userRepository,
        ILogger<ResendVerificationCommandHandler> logger,
        IEmailSender emailSender,
        IJwtGenerator jwtGenerator)
    {
        _userRepository = userRepository;
        _logger = logger;
        _emailSender = emailSender;
        _jwtGenerator = jwtGenerator;
    }

    public async Task<Result<bool>> Handle(ResendVerificationCommand request, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Processing resend verification request for: {Email}", request.Email);

            // Get user by email (but don't reveal if user exists or not for security)
            var user = await _userRepository.GetByEmailAsync(request.Email, cancellationToken);
            
            if (user == null)
            {
                // Don't reveal that user doesn't exist - but log for monitoring
                _logger.LogInformation("Resend verification requested for non-existent email: {Email}", request.Email);
                return Result<bool>.Success(false, "Email processed");
            }

            if (user.EmailConfirmed)
            {
                // Don't reveal that email is already confirmed - but log for monitoring
                _logger.LogInformation("Resend verification requested for already confirmed email: {Email}", request.Email);
                return Result<bool>.Success(false, "Email processed");
            }

            // Generate new confirmation token
            var (confirmationToken, expiresAt) = await _jwtGenerator.GenerateConfirmationTokenAsync(user);

            // Send confirmation email
            var applicationUrl = request.ApplicationUrl ?? "https://localhost:7109";
            var confirmationLink = $"{applicationUrl}/confirm-email?token={confirmationToken}";
            
            await _emailSender.SendEmailConfirmationAsync(user.Email, user.Username, confirmationLink);
            
            _logger.LogInformation("Verification email resent successfully to: {Email}", request.Email);
            
            return Result<bool>.Success(true, "Verification email sent");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during resend verification for: {Email}", request.Email);
            return Result<bool>.Success(false, "Email processed"); // Don't reveal errors
        }
    }
}