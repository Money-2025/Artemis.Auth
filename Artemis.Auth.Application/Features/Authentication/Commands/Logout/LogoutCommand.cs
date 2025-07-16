using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Authentication.Commands.Logout;

/// <summary>
/// Command for user logout
/// </summary>
public class LogoutCommand : IRequest<Result<LogoutDto>>
{
    public Guid UserId { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public bool LogoutAllDevices { get; set; } = false;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// Logout response data transfer object
/// </summary>
public class LogoutDto
{
    public Guid UserId { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime LoggedOutAt { get; set; }
    public bool Success { get; set; }
    public bool AllDevicesLoggedOut { get; set; }
}