using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Admin.Commands.RemoveUserRole;

public class RemoveUserRoleCommandHandler : IRequestHandler<RemoveUserRoleCommand, Result>
{
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly ILogger<RemoveUserRoleCommandHandler> _logger;

    public RemoveUserRoleCommandHandler(
        IUserRepository userRepository,
        IRoleRepository roleRepository,
        ILogger<RemoveUserRoleCommandHandler> logger)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _logger = logger;
    }

    public async Task<Result> Handle(RemoveUserRoleCommand request, CancellationToken cancellationToken)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            
            if (user == null)
            {
                return Result.Failure("User not found");
            }

            var role = await _roleRepository.GetByIdAsync(request.RoleId);
            
            if (role == null)
            {
                return Result.Failure("Role not found");
            }

            // Remove role from user using existing repository method
            await _roleRepository.RemoveRoleFromUserAsync(request.UserId, request.RoleId);

            return Result.Success("Role removed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing role {RoleId} from user {UserId} by admin {RemovedBy}", request.RoleId, request.UserId, request.RemovedBy);
            return Result.Failure("Failed to remove role");
        }
    }
}