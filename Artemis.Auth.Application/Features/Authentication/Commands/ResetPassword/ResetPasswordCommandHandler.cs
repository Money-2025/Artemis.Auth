using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Domain.Entities;
using System.Security.Cryptography;
using System.Text;

namespace Artemis.Auth.Application.Features.Authentication.Commands.ResetPassword;

public class ResetPasswordCommandHandler : IRequestHandler<ResetPasswordCommand, Result<ResetPasswordDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<ResetPasswordCommandHandler> _logger;

    public ResetPasswordCommandHandler(
        IUserRepository userRepository,
        ILogger<ResetPasswordCommandHandler> logger)
    {
        _userRepository = userRepository;
        _logger = logger;
    }

    public async Task<Result<ResetPasswordDto>> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        try
        {
            // Get user by email
            var user = await _userRepository.GetByEmailAsync(request.Email, cancellationToken);
            if (user == null)
            {
                return Result<ResetPasswordDto>.Failure("Invalid reset token or email");
            }

            // Check if user is locked out
            if (user.IsLockedOut())
            {
                return Result<ResetPasswordDto>.Failure("Account is locked");
            }

            // Validate reset token (in a real implementation, you'd validate against stored token)
            if (string.IsNullOrEmpty(request.Token) || request.Token.Length < 32)
            {
                return Result<ResetPasswordDto>.Failure("Invalid reset token");
            }

            // Hash new password
            var newPasswordHash = HashPassword(request.NewPassword);

            // Update password in database
            await _userRepository.UpdatePasswordAsync(user.Id, newPasswordHash, cancellationToken);

            // Update security stamp to invalidate existing tokens
            await _userRepository.UpdateSecurityStampAsync(user.Id, cancellationToken);

            // Reset failed login count
            user.ResetFailedLoginCount();
            await _userRepository.UpdateAsync(user, cancellationToken);

            var result = new ResetPasswordDto
            {
                Email = request.Email,
                Message = "Password has been reset successfully. You can now login with your new password.",
                ResetAt = DateTime.UtcNow,
                Success = true
            };

            _logger.LogInformation("Password reset successfully for user: {Email}", request.Email);

            return Result<ResetPasswordDto>.Success(result, "Password reset successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during password reset for {Email}", request.Email);
            return Result<ResetPasswordDto>.Failure("Password reset failed. Please try again.");
        }
    }

    private static string HashPassword(string password)
    {
        // Simple SHA256 hash with salt (in production, use BCrypt or similar)
        using var sha256 = SHA256.Create();
        var salt = "AuthMicroserviceSalt"; // In production, use random salt per user
        var saltedPassword = password + salt;
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(saltedPassword));
        return Convert.ToBase64String(hash);
    }
}