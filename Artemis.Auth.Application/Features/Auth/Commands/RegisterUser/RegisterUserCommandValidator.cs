using FluentValidation;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Domain.Common;

namespace Artemis.Auth.Application.Features.Auth.Commands.RegisterUser;

public class RegisterUserCommandValidator : AbstractValidator<RegisterUserCommand>
{
    private readonly IUserRepository _userRepository;

    public RegisterUserCommandValidator(IUserRepository userRepository)
    {
        _userRepository = userRepository;

        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required")
            .Length(3, 50).WithMessage("Username must be between 3 and 50 characters")
            .Must(BeValidUsername).WithMessage("Username can only contain letters, numbers, dots, hyphens, and underscores")
            .MustAsync(BeUniqueUsername).WithMessage("Username is already taken");

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required")
            .EmailAddress().WithMessage("Invalid email format")
            .Must(BeValidEmail).WithMessage("Invalid email format")
            .MustAsync(BeUniqueEmail).WithMessage("Email is already taken");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required")
            .Must(BeStrongPassword).WithMessage("Password must be at least 8 characters long and contain uppercase, lowercase, number and special character");

        RuleFor(x => x.ConfirmPassword)
            .NotEmpty().WithMessage("Password confirmation is required")
            .Equal(x => x.Password).WithMessage("Passwords do not match");

        RuleFor(x => x.PhoneNumber)
            .Must(BeValidPhoneNumber).When(x => !string.IsNullOrEmpty(x.PhoneNumber))
            .WithMessage("Invalid phone number format")
            .MustAsync(BeUniquePhoneNumber).When(x => !string.IsNullOrEmpty(x.PhoneNumber))
            .WithMessage("Phone number is already taken");

        RuleFor(x => x.FirstName)
            .MaximumLength(100).WithMessage("First name cannot exceed 100 characters")
            .When(x => !string.IsNullOrEmpty(x.FirstName));

        RuleFor(x => x.LastName)
            .MaximumLength(100).WithMessage("Last name cannot exceed 100 characters")
            .When(x => !string.IsNullOrEmpty(x.LastName));

        RuleFor(x => x.AcceptTerms)
            .Equal(true).WithMessage("You must accept the terms and conditions");
    }

    private static bool BeValidUsername(string username)
    {
        return username.IsValidUsername();
    }

    private static bool BeValidEmail(string email)
    {
        return email.IsValidEmail();
    }

    private static bool BeValidPhoneNumber(string? phoneNumber)
    {
        return !string.IsNullOrEmpty(phoneNumber) && phoneNumber.IsValidPhoneNumber();
    }

    private static bool BeStrongPassword(string password)
    {
        return password.IsStrongPassword();
    }

    private async Task<bool> BeUniqueUsername(string username, CancellationToken cancellationToken)
    {
        return await _userRepository.IsUsernameUniqueAsync(username, cancellationToken: cancellationToken);
    }

    private async Task<bool> BeUniqueEmail(string email, CancellationToken cancellationToken)
    {
        return await _userRepository.IsEmailUniqueAsync(email, cancellationToken: cancellationToken);
    }

    private async Task<bool> BeUniquePhoneNumber(string? phoneNumber, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(phoneNumber))
            return true;
        return await _userRepository.IsPhoneNumberUniqueAsync(phoneNumber, cancellationToken: cancellationToken);
    }
}