using System.Security.Claims;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Features.Authentication.Commands.VerifyEmail;
using MediatR;
using Microsoft.Extensions.Logging;

public class VerifyEmailCommandHandler : IRequestHandler<VerifyEmailCommand, Result<VerifyEmailDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<VerifyEmailCommandHandler> _logger;
    private readonly IJwtGenerator _jwtGenerator;

    public VerifyEmailCommandHandler(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        ILogger<VerifyEmailCommandHandler> logger,
        IJwtGenerator jwtGenerator)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _logger = logger;
        _jwtGenerator = jwtGenerator;
    }

    public async Task<Result<VerifyEmailDto>> Handle(VerifyEmailCommand request, CancellationToken cancellationToken)
    {
        try
        {
            // 1. Token validate & principal al
            var (isValid, principal, error) = await _jwtGenerator
                .ValidateAndGetPrincipalAsync(request.Token, "confirmation");

            if (!isValid || principal == null)
            {
                _logger.LogWarning("Email verification failed: {Reason}", error);
                return Result<VerifyEmailDto>.Failure(error ?? "Invalid or expired verification token");
            }

            // 2. UserId claim
            var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)
                              ?? principal.FindFirst("sub");
            if (userIdClaim == null || !Guid.TryParse(userIdClaim.Value, out var userId))
            {
                _logger.LogWarning("Email verification failed: missing or invalid user id claim");
                return Result<VerifyEmailDto>.Failure("Invalid verification token");
            }

            // 3. Security stamp claim (opsiyonel ama önerilir)
            var stampClaim = principal.FindFirst("artemis:security_stamp")?.Value;

            // 4. Email claim (isteğe bağlı doğrulama)
            var emailClaim = principal.FindFirst("artemis:email")?.Value;

            // 5. User fetch
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                _logger.LogWarning("Email verification failed: user not found (ID: {UserId})", userId);
                return Result<VerifyEmailDto>.Failure("Invalid verification token");
            }

            // 6. Security stamp mismatch
            if (!string.IsNullOrEmpty(stampClaim) &&
                !string.Equals(stampClaim, user.SecurityStamp, StringComparison.Ordinal))
            {
                _logger.LogWarning("Email verification failed: security stamp mismatch for user {UserId}", userId);
                return Result<VerifyEmailDto>.Failure("Invalid or expired verification token");
            }

            // 7. (Opsiyonel) token email claim DB ile uyumlu mu?
            if (!string.IsNullOrEmpty(emailClaim) &&
                !string.Equals(emailClaim, user.Email, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Email verification failed: email claim mismatch for user {UserId}", userId);
                return Result<VerifyEmailDto>.Failure("Invalid verification token");
            }

            // 8. Already verified?
            if (user.EmailConfirmed)
            {
                var already = new VerifyEmailDto
                {
                    Email = user.Email,
                    Message = "Email address is already verified",
                    VerifiedAt = DateTime.UtcNow,
                    Success = true,
                    AccountActivated = true
                };
                return Result<VerifyEmailDto>.Success(already, "Email already verified");
            }

            // 9. Update user object directly (no redundant DB calls)
            user.EmailConfirmed = true;
            user.SecurityStamp = Guid.NewGuid().ToString();

            // 10. Update entity in repository to enable change tracking
            await _userRepository.UpdateAsync(user, cancellationToken);

            // 11. Save all changes to database
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Email verified and security stamp updated for user {UserId}", userId);

            var dto = new VerifyEmailDto
            {
                Email = user.Email,
                Message = "Email address has been verified successfully. Your account is now active.",
                VerifiedAt = DateTime.UtcNow,
                Success = true,
                AccountActivated = true
            };

            return Result<VerifyEmailDto>.Success(dto, "Email verified successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during email verification (token processing)");
            return Result<VerifyEmailDto>.Failure("Email verification failed. Please try again.");
        }
    }
}
