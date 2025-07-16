using MediatR;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Admin.Commands.DeleteUser;

public class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand, Result>
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<DeleteUserCommandHandler> _logger;

    public DeleteUserCommandHandler(
        IUserRepository userRepository,
        ILogger<DeleteUserCommandHandler> logger)
    {
        _userRepository = userRepository;
        _logger = logger;
    }

    public async Task<Result> Handle(DeleteUserCommand request, CancellationToken cancellationToken)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            
            if (user == null)
            {
                return Result.Failure("User not found");
            }

            // Soft delete using audit fields
            user.IsDeleted = true;
            user.DeletedAt = DateTime.UtcNow;
            user.DeletedBy = request.DeletedBy;

            await _userRepository.UpdateAsync(user);

            return Result.Success("User deleted successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting user {UserId} by admin {DeletedBy}", request.UserId, request.DeletedBy);
            return Result.Failure("Failed to delete user");
        }
    }
}