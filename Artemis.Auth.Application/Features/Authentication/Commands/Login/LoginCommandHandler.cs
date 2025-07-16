using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Authentication.Commands.Login;

/// <summary>
/// Handler for login command
/// </summary>
public class LoginCommandHandler : IRequestHandler<LoginCommand, Result<LoginDto>>
{
    public async Task<Result<LoginDto>> Handle(LoginCommand request, CancellationToken cancellationToken)
    {
        // TODO: Implement actual login logic
        // This is a placeholder implementation
        
        if (string.IsNullOrEmpty(request.UsernameOrEmail) || string.IsNullOrEmpty(request.Password))
        {
            return Result<LoginDto>.Failure("Username/email and password are required");
        }

        // Simulate authentication
        await Task.Delay(100, cancellationToken);

        var loginDto = new LoginDto
        {
            AccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            RefreshToken = Guid.NewGuid().ToString(),
            ExpiresAt = DateTime.UtcNow.AddHours(24),
            TokenType = "Bearer",
            User = new UserInfoDto
            {
                Id = Guid.NewGuid(),
                Username = request.UsernameOrEmail,
                Email = request.UsernameOrEmail,
                FirstName = "John",
                LastName = "Doe",
                Roles = new[] { "User" },
                Permissions = new[] { "read:profile", "write:profile" },
                IsEmailVerified = true,
                TwoFactorEnabled = false
            },
            RequiresTwoFactor = false,
            AvailableTwoFactorProviders = Array.Empty<string>()
        };

        return Result<LoginDto>.Success(loginDto, "Login successful");
    }
}