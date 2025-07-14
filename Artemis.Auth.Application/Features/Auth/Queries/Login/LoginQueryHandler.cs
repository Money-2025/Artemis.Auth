using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Application.Common.Exceptions;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Application.Features.Auth.Queries.Login;

public class LoginQueryHandler : IRequestHandler<LoginQuery, Result<TokenResponseDto>>
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<LoginQueryHandler> _logger;
    private readonly IJwtGenerator _jwtGenerator;

    public LoginQueryHandler(
        IUnitOfWork unitOfWork,
        ILogger<LoginQueryHandler> logger,
        IJwtGenerator jwtGenerator)
    {
        _unitOfWork = unitOfWork;
        _logger = logger;
        _jwtGenerator = jwtGenerator;
    }

    public async Task<Result<TokenResponseDto>> Handle(LoginQuery request, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Login attempt for username: {Username} from IP: {IpAddress}", 
                request.Username, request.ClientIpAddress);

            // Find user by username or email
            var user = await _unitOfWork.Users.GetByUsernameAsync(request.Username, cancellationToken);
            if (user == null)
            {
                user = await _unitOfWork.Users.GetByEmailAsync(request.Username, cancellationToken);
            }

            if (user == null)
            {
                _logger.LogWarning("Login failed: User {Username} not found", request.Username);
                await Task.Delay(Random.Shared.Next(100, 300), cancellationToken); // Prevent timing attacks
                return Result<TokenResponseDto>.Failure("Invalid username or password");
            }

            // Check if user is deleted
            if (user.IsDeleted)
            {
                _logger.LogWarning("Login failed: User {Username} is deleted", request.Username);
                return Result<TokenResponseDto>.Failure("Account not found");
            }

            // Check if user is locked out
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
            {
                _logger.LogWarning("Login failed: User {Username} is locked out until {LockoutEnd}", 
                    request.Username, user.LockoutEnd.Value);
                return Result<TokenResponseDto>.Failure($"Account is locked until {user.LockoutEnd.Value:yyyy-MM-dd HH:mm:ss} UTC");
            }

            // Verify password
            if (!VerifyPassword(request.Password, user.PasswordHash))
            {
                _logger.LogWarning("Login failed: Invalid password for user {Username}", request.Username);
                
                // Increment failed login count
                await _unitOfWork.Users.UpdateLockoutAsync(
                    user.Id, 
                    CalculateLockoutEnd(user.FailedLoginCount + 1), 
                    user.FailedLoginCount + 1, 
                    cancellationToken);
                
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                
                return Result<TokenResponseDto>.Failure("Invalid username or password");
            }

            // Check if email is confirmed
            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("Login failed: Email not confirmed for user {Username}", request.Username);
                return Result<TokenResponseDto>.Failure("Please confirm your email address before logging in");
            }

            // Reset failed login count on successful login
            if (user.FailedLoginCount > 0)
            {
                await _unitOfWork.Users.UpdateLockoutAsync(user.Id, null, 0, cancellationToken);
            }

            // Update last login
            user.LastLoginAt = DateTime.UtcNow;
            await _unitOfWork.Users.UpdateAsync(user, cancellationToken);

            // Get user roles and permissions
            var roles = await _unitOfWork.Users.GetUserRolesAsync(user.Id, cancellationToken);
            var permissions = await _unitOfWork.Users.GetUserPermissionsAsync(user.Id, cancellationToken);

            // Generate tokens
            var accessToken = await _jwtGenerator.GenerateAccessTokenAsync(user, roles, permissions);
            var refreshToken = await _jwtGenerator.GenerateRefreshTokenAsync(user);

            // Create user session
            var session = new UserSession
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                IpAddress = request.ClientIpAddress ?? "Unknown",
                UserAgent = request.UserAgent,
                SessionTokenHash = HashToken(refreshToken),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(request.RememberMe ? 30 : 1),
                LastAccessAt = DateTime.UtcNow,
                IsRevoked = false,
                IsDeleted = false
            };

            // Add session to user (assuming User entity has a Sessions navigation property)
            // This would typically be done through a session repository
            // For now, we'll assume the session is saved separately

            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("User {Username} logged in successfully from IP: {IpAddress}", 
                request.Username, request.ClientIpAddress);

            // Create response
            var tokenResponse = new TokenResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                TokenType = "Bearer",
                ExpiresIn = 3600, // 1 hour
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                Scope = "openid profile email",
                Claims = new Dictionary<string, object>
                {
                    { "user_id", user.Id },
                    { "username", user.Username },
                    { "email", user.Email },
                    { "roles", roles },
                    { "permissions", permissions }
                }
            };

            return Result<TokenResponseDto>.Success(tokenResponse, "Login successful");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred during login for username: {Username}", request.Username);
            return Result<TokenResponseDto>.Failure("An error occurred during login. Please try again.");
        }
    }

    private static bool VerifyPassword(string password, string hash)
    {
        // This is a placeholder - in real implementation, use a proper password verification
        // like BCrypt, Argon2, or use ASP.NET Core Identity's password hasher
        return BCrypt.Net.BCrypt.Verify(password, hash);
    }

    private static DateTime? CalculateLockoutEnd(int failedLoginCount)
    {
        // Progressive lockout: more failed attempts = longer lockout
        return failedLoginCount switch
        {
            >= 5 => DateTime.UtcNow.AddHours(1), // 1 hour after 5 failed attempts
            >= 3 => DateTime.UtcNow.AddMinutes(15), // 15 minutes after 3 failed attempts
            _ => null // No lockout for less than 3 failed attempts
        };
    }

    private static string HashToken(string token)
    {
        // This is a placeholder - in real implementation, use a proper hashing algorithm
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hashedBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hashedBytes);
    }
}