using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Auth.Commands.ResetPassword;

public class ResetPasswordCommand : IRequest<Result<string>>
{
    public string Token { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
    public string? ClientIpAddress { get; set; }
    public string? UserAgent { get; set; }
}