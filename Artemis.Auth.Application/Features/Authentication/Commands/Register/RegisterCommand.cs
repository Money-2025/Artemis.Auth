using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Authentication.Commands.Register;

/// <summary>
/// Command for user registration
/// </summary>
public class RegisterCommand : IRequest<Result<RegisterDto>>
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? PhoneNumber { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public bool AcceptTerms { get; set; }
}

/// <summary>
/// Registration response data transfer object
/// </summary>
public class RegisterDto
{
    public Guid UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailConfirmationRequired { get; set; }
    public string? EmailConfirmationToken { get; set; }
    public DateTime RegisteredAt { get; set; }
    public string Message { get; set; } = string.Empty;
}