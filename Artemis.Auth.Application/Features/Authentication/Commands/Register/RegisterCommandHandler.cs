using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Domain.Entities;
using System.Security.Cryptography;

namespace Artemis.Auth.Application.Features.Authentication.Commands.Register;

public class RegisterCommandHandler : IRequestHandler<RegisterCommand, Result<RegisterDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<RegisterCommandHandler> _logger;
    public RegisterCommandHandler(
        IUserRepository userRepository,
        IEmailSender emailSender,
        ILogger<RegisterCommandHandler> logger)
    {
        _userRepository = userRepository;
        _emailSender = emailSender;
        _logger = logger;
    }

    public async Task<Result<RegisterDto>> Handle(RegisterCommand request, CancellationToken cancellationToken)
    {
        try
        {
            // Check if username already exists
            if (!await _userRepository.IsUsernameUniqueAsync(request.Username, cancellationToken: cancellationToken))
            {
                return Result<RegisterDto>.Failure("Username is already taken");
            }

            // Check if email already exists
            if (!await _userRepository.IsEmailUniqueAsync(request.Email, cancellationToken: cancellationToken))
            {
                return Result<RegisterDto>.Failure("Email is already registered");
            }

            // Check if phone number already exists (if provided)
            if (!string.IsNullOrEmpty(request.PhoneNumber) && 
                !await _userRepository.IsPhoneNumberUniqueAsync(request.PhoneNumber, cancellationToken: cancellationToken))
            {
                return Result<RegisterDto>.Failure("Phone number is already registered");
            }

            // Create new user
            var user = new User
            {
                Id = Guid.NewGuid(),
                Username = request.Username,
                NormalizedUsername = request.Username.ToUpperInvariant(),
                Email = request.Email,
                NormalizedEmail = request.Email.ToUpperInvariant(),
                PhoneNumber = request.PhoneNumber,
                EmailConfirmed = false,
                PhoneNumberConfirmed = false,
                TwoFactorEnabled = false,
                SecurityStamp = GenerateSecurityStamp(),
                FailedLoginCount = 0,
                CreatedAt = DateTime.UtcNow,
                CreatedBy = Guid.Empty, // System registration
                IsDeleted = false
            };

            // Hash password using simple BCrypt-like approach
            user.PasswordHash = HashPassword(request.Password);

            // Save user
            await _userRepository.CreateAsync(user, cancellationToken);

            // Generate email confirmation token
            var confirmationToken = GenerateEmailConfirmationToken();

            // Send confirmation email
            await _emailSender.SendEmailConfirmationAsync(
                user.Email,
                user.Username,
                confirmationToken);

            var result = new RegisterDto
            {
                UserId = user.Id,
                Username = user.Username,
                Email = user.Email,
                EmailConfirmationRequired = true,
                EmailConfirmationToken = confirmationToken,
                RegisteredAt = user.CreatedAt,
                Message = "Registration successful. Please check your email to confirm your account."
            };

            _logger.LogInformation("User registered successfully: {Username} ({Email})", user.Username, user.Email);

            return Result<RegisterDto>.Success(result, "User registered successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user registration for {Username} ({Email})", request.Username, request.Email);
            return Result<RegisterDto>.Failure("Registration failed. Please try again.");
        }
    }

    private static string GenerateSecurityStamp()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }

    private static string GenerateEmailConfirmationToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }

    private static string HashPassword(string password)
    {
        // Use BCrypt for secure password hashing
        return BCrypt.Net.BCrypt.HashPassword(password);
    }
}