using MediatR;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Auth.Queries.Login;

public class LoginQuery : IRequest<Result<TokenResponseDto>>
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool RememberMe { get; set; } = false;
    public string? ClientIpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? DeviceType { get; set; }
    public string? DeviceName { get; set; }
}