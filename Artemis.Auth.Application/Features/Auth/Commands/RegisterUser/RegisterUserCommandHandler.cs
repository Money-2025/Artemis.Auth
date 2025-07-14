using MediatR;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Application.Common.Exceptions;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Domain.Common;

namespace Artemis.Auth.Application.Features.Auth.Commands.RegisterUser;

public class RegisterUserCommandHandler : IRequestHandler<RegisterUserCommand, Result<UserProfileDto>>
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IMapper _mapper;
    private readonly ILogger<RegisterUserCommandHandler> _logger;
    private readonly IEmailSender _emailSender;
    private readonly IJwtGenerator _jwtGenerator;

    public RegisterUserCommandHandler(
        IUnitOfWork unitOfWork,
        IMapper mapper,
        ILogger<RegisterUserCommandHandler> logger,
        IEmailSender emailSender,
        IJwtGenerator jwtGenerator)
    {
        _unitOfWork = unitOfWork;
        _mapper = mapper;
        _logger = logger;
        _emailSender = emailSender;
        _jwtGenerator = jwtGenerator;
    }

    public async Task<Result<UserProfileDto>> Handle(RegisterUserCommand request, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Starting user registration for username: {Username}", request.Username);

            // Check if username already exists
            var existingUser = await _unitOfWork.Users.GetByUsernameAsync(request.Username, cancellationToken);
            if (existingUser != null)
            {
                _logger.LogWarning("Registration failed: Username {Username} already exists", request.Username);
                return Result<UserProfileDto>.Failure("Username is already taken");
            }

            // Check if email already exists
            existingUser = await _unitOfWork.Users.GetByEmailAsync(request.Email, cancellationToken);
            if (existingUser != null)
            {
                _logger.LogWarning("Registration failed: Email {Email} already exists", request.Email);
                return Result<UserProfileDto>.Failure("Email is already taken");
            }

            // Check if phone number already exists (if provided)
            if (!string.IsNullOrEmpty(request.PhoneNumber))
            {
                existingUser = await _unitOfWork.Users.GetByPhoneNumberAsync(request.PhoneNumber, cancellationToken);
                if (existingUser != null)
                {
                    _logger.LogWarning("Registration failed: Phone number {PhoneNumber} already exists", request.PhoneNumber);
                    return Result<UserProfileDto>.Failure("Phone number is already taken");
                }
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
                // FirstName = request.FirstName,  // Not available in User entity
                // LastName = request.LastName,    // Not available in User entity
                EmailConfirmed = false,
                PhoneNumberConfirmed = false,
                TwoFactorEnabled = false,
                SecurityStamp = Guid.NewGuid().ToString(),
                PasswordHash = HashPassword(request.Password),
                CreatedAt = DateTime.UtcNow,
                IsDeleted = false,
                FailedLoginCount = 0
            };

            // Save user to database
            await _unitOfWork.Users.CreateAsync(user, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("User {Username} registered successfully with ID: {UserId}", request.Username, user.Id);

            // Generate email confirmation token
            var (confirmationToken, expiresAt) = await _jwtGenerator.GenerateConfirmationTokenAsync(user);

            // Send confirmation email
            try
            {
                var confirmationLink = $"https://your-app.com/confirm-email?token={confirmationToken}";
                await _emailSender.SendEmailConfirmationAsync(user.Email, user.Username, confirmationLink);
                _logger.LogInformation("Confirmation email sent to {Email} for user {Username}", user.Email, user.Username);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send confirmation email to {Email} for user {Username}", user.Email, user.Username);
                // Don't fail the registration if email sending fails
            }

            // Map to DTO
            var userDto = _mapper.Map<UserProfileDto>(user);
            userDto.Roles = new List<string>(); // No roles assigned by default
            userDto.Permissions = new List<string>(); // No permissions assigned by default

            return Result<UserProfileDto>.Success(userDto, "User registered successfully. Please check your email to confirm your account.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred during user registration for username: {Username}", request.Username);
            return Result<UserProfileDto>.Failure("An error occurred during registration. Please try again.");
        }
    }

    private static string HashPassword(string password)
    {
        // This is a placeholder - in real implementation, use a proper password hashing library
        // like BCrypt, Argon2, or use ASP.NET Core Identity's password hasher
        return BCrypt.Net.BCrypt.HashPassword(password);
    }
}