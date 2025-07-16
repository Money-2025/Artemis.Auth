using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Contracts.Infrastructure;
using System.Security.Cryptography;

namespace Artemis.Auth.Application.Features.Authentication.Commands.ForgotPassword;

public class ForgotPasswordCommandHandler : IRequestHandler<ForgotPasswordCommand, Result<ForgotPasswordDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<ForgotPasswordCommandHandler> _logger;

    public ForgotPasswordCommandHandler(
        IUserRepository userRepository,
        IEmailSender emailSender,
        ILogger<ForgotPasswordCommandHandler> logger)
    {
        _userRepository = userRepository;
        _emailSender = emailSender;
        _logger = logger;
    }

    public async Task<Result<ForgotPasswordDto>> Handle(ForgotPasswordCommand request, CancellationToken cancellationToken)
    {
        try
        {
            // Always return success for security reasons (don't reveal if email exists)
            var result = new ForgotPasswordDto
            {
                Email = request.Email,
                Message = "If the email address exists in our system, you will receive a password reset link.",
                RequestedAt = DateTime.UtcNow,
                EmailSent = false
            };

            // Check if user exists
            var user = await _userRepository.GetByEmailAsync(request.Email, cancellationToken);
            if (user == null)
            {
                _logger.LogWarning("Password reset requested for non-existent email: {Email}", request.Email);
                return Result<ForgotPasswordDto>.Success(result, result.Message);
            }

            // Check if user is locked out
            if (user.IsLockedOut())
            {
                _logger.LogWarning("Password reset requested for locked account: {Email}", request.Email);
                return Result<ForgotPasswordDto>.Success(result, result.Message);
            }

            // Generate password reset token
            var resetToken = GeneratePasswordResetToken();

            // Store the reset token (in a real implementation, you'd store this in the database)
            // For now, we'll just log it and send it via email
            _logger.LogInformation("Password reset token generated for {Email}: {Token}", request.Email, resetToken);

            // Send password reset email
            await _emailSender.SendPasswordResetAsync(
                user.Email,
                user.Username,
                resetToken);

            result.EmailSent = true;

            _logger.LogInformation("Password reset email sent to: {Email}", request.Email);

            return Result<ForgotPasswordDto>.Success(result, result.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during password reset request for {Email}", request.Email);
            
            // Always return success for security reasons
            var result = new ForgotPasswordDto
            {
                Email = request.Email,
                Message = "If the email address exists in our system, you will receive a password reset link.",
                RequestedAt = DateTime.UtcNow,
                EmailSent = false
            };

            return Result<ForgotPasswordDto>.Success(result, result.Message);
        }
    }

    private static string GeneratePasswordResetToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }
}