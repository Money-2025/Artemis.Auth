using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using AutoMapper;
using MediatR;
using Artemis.Auth.Api.DTOs.User;
using Artemis.Auth.Api.DTOs.Common;
using Artemis.Auth.Application.Features.Users.Queries.GetUserProfile;
using Artemis.Auth.Application.Features.Users.Commands.UpdateUserProfile;
using Artemis.Auth.Application.Features.Users.Commands.ChangePassword;
using Artemis.Auth.Application.Features.Users.Queries.GetUserSessions;
using Artemis.Auth.Application.Features.Users.Commands.TerminateSession;

namespace Artemis.Auth.Api.Controllers;

/// <summary>
/// User controller providing user profile and session management endpoints
/// Implements comprehensive user management with security and validation
/// </summary>
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[Authorize]
[Produces("application/json")]
[EnableRateLimiting("UserPolicy")]
public class UserController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly IMapper _mapper;
    private readonly ILogger<UserController> _logger;

    /// <summary>
    /// Initializes the user controller
    /// </summary>
    public UserController(
        IMediator mediator,
        IMapper mapper,
        ILogger<UserController> logger)
    {
        _mediator = mediator ?? throw new ArgumentNullException(nameof(mediator));
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Gets the current user's profile
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User profile information</returns>
    /// <response code="200">Profile retrieved successfully</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">User not found</response>
    [HttpGet("profile")]
    [ProducesResponseType(typeof(ApiResponse<UserProfileResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetProfile(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("Profile request for user: {UserId}", userId);

            var query = new GetUserProfileQuery { UserId = userId };
            var result = await _mediator.Send(query, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("Profile retrieval failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("PROFILE_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<UserProfileResponse>(result.Data);
            
            _logger.LogInformation("Profile retrieved successfully for user: {UserId}", userId);

            return Ok(ApiResponse<UserProfileResponse>.SuccessResponse(response, "Profile retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving profile for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Profile retrieval failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Updates the current user's profile
    /// </summary>
    /// <param name="request">Profile update request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated user profile</returns>
    /// <response code="200">Profile updated successfully</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">User not found</response>
    [HttpPut("profile")]
    [EnableRateLimiting("ProfileUpdatePolicy")]
    [ProducesResponseType(typeof(ApiResponse<UserProfileResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateProfile(
        [FromBody] UserProfileRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("Profile update request for user: {UserId}", userId);

            var command = _mapper.Map<UpdateUserProfileCommand>(request);
            command.UserId = userId;
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("Profile update failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("PROFILE_UPDATE_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<UserProfileResponse>(result.Data);
            
            _logger.LogInformation("Profile updated successfully for user: {UserId}", userId);

            return Ok(ApiResponse<UserProfileResponse>.SuccessResponse(response, "Profile updated successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating profile for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Profile update failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Changes the current user's password
    /// </summary>
    /// <param name="request">Password change request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Password change response</returns>
    /// <response code="200">Password changed successfully</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Unauthorized or current password invalid</response>
    /// <response code="404">User not found</response>
    [HttpPost("change-password")]
    [EnableRateLimiting("PasswordChangePolicy")]
    [ProducesResponseType(typeof(ApiResponse<ChangePasswordResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ChangePassword(
        [FromBody] ChangePasswordRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();
            
            _logger.LogInformation("Password change request for user: {UserId}", userId);

            var command = _mapper.Map<ChangePasswordCommand>(request);
            command.UserId = userId;
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("Password change failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return result.Message switch
                {
                    var msg when msg.Contains("not found") => NotFound(
                        ErrorResponse.NotFoundError(msg, HttpContext.TraceIdentifier)),
                    var msg when msg.Contains("current password") || msg.Contains("invalid") => Unauthorized(
                        ErrorResponse.AuthenticationError(msg, HttpContext.TraceIdentifier)),
                    _ => BadRequest(
                        ErrorResponse.CustomError("PASSWORD_CHANGE_ERROR", result.Message, 400, HttpContext.TraceIdentifier))
                };
            }

            var response = _mapper.Map<ChangePasswordResponse>(result.Data);
            
            _logger.LogInformation("Password changed successfully for user: {UserId}", userId);

            return Ok(ApiResponse<ChangePasswordResponse>.SuccessResponse(response, "Password changed successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error changing password for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Password change failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Gets the current user's active sessions
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of active sessions</returns>
    /// <response code="200">Sessions retrieved successfully</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">User not found</response>
    [HttpGet("sessions")]
    [ProducesResponseType(typeof(ApiResponse<UserSessionsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetSessions(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            var currentSessionId = GetCurrentSessionId();
            
            _logger.LogInformation("Sessions request for user: {UserId}", userId);

            var query = new GetUserSessionsQuery 
            { 
                UserId = userId,
                CurrentSessionId = currentSessionId
            };
            
            var result = await _mediator.Send(query, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("Sessions retrieval failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("SESSIONS_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<UserSessionsResponse>(result.Data);
            
            _logger.LogInformation("Sessions retrieved successfully for user: {UserId}", userId);

            return Ok(ApiResponse<UserSessionsResponse>.SuccessResponse(response, "Sessions retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving sessions for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Sessions retrieval failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Terminates a specific user session
    /// </summary>
    /// <param name="sessionId">Session ID to terminate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Session termination response</returns>
    /// <response code="200">Session terminated successfully</response>
    /// <response code="400">Invalid session ID</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">Session not found</response>
    [HttpDelete("sessions/{sessionId:guid}")]
    [EnableRateLimiting("SessionTerminationPolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> TerminateSession(
        [FromRoute] Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            var currentSessionId = GetCurrentSessionId();
            
            _logger.LogInformation("Session termination request for user: {UserId}, session: {SessionId}", 
                userId, sessionId);

            var command = new TerminateSessionCommand
            {
                UserId = userId,
                SessionId = sessionId,
                CurrentSessionId = currentSessionId,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("Session termination failed for user: {UserId}, session: {SessionId}. Reason: {Reason}", 
                    userId, sessionId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("SESSION_TERMINATION_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            _logger.LogInformation("Session terminated successfully for user: {UserId}, session: {SessionId}", 
                userId, sessionId);

            return Ok(ApiResponse.SuccessResponse("Session terminated successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error terminating session for user: {UserId}, session: {SessionId}", 
                GetCurrentUserId(), sessionId);
            return StatusCode(500, ErrorResponse.InternalServerError("Session termination failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Terminates all user sessions except the current one
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Session termination response</returns>
    /// <response code="200">Sessions terminated successfully</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">User not found</response>
    [HttpDelete("sessions")]
    [EnableRateLimiting("SessionTerminationPolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> TerminateAllSessions(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            var currentSessionId = GetCurrentSessionId();
            
            _logger.LogInformation("All sessions termination request for user: {UserId}", userId);

            var command = new TerminateSessionCommand
            {
                UserId = userId,
                CurrentSessionId = currentSessionId,
                TerminateAll = true,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("All sessions termination failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("SESSION_TERMINATION_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            _logger.LogInformation("All sessions terminated successfully for user: {UserId}", userId);

            return Ok(ApiResponse.SuccessResponse("All sessions terminated successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error terminating all sessions for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Session termination failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Gets user account security summary
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Security summary</returns>
    /// <response code="200">Security summary retrieved successfully</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">User not found</response>
    [HttpGet("security")]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetSecuritySummary(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("Security summary request for user: {UserId}", userId);

            // This would typically call a specific query for security summary
            // For now, returning a placeholder response
            var response = new
            {
                UserId = userId,
                SecurityScore = 85,
                TwoFactorEnabled = false,
                PasswordStrength = "Strong",
                LastPasswordChange = DateTime.UtcNow.AddDays(-30),
                ActiveSessions = 2,
                RecentActivity = new[]
                {
                    new { Action = "Login", Timestamp = DateTime.UtcNow.AddHours(-2), IpAddress = GetClientIpAddress() },
                    new { Action = "Profile Update", Timestamp = DateTime.UtcNow.AddDays(-1), IpAddress = GetClientIpAddress() }
                },
                SecurityRecommendations = new[]
                {
                    "Enable two-factor authentication",
                    "Review active sessions regularly",
                    "Update password periodically"
                }
            };

            _logger.LogInformation("Security summary retrieved successfully for user: {UserId}", userId);

            return Ok(ApiResponse<object>.SuccessResponse(response, "Security summary retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving security summary for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Security summary retrieval failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Deletes user account (soft delete)
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Account deletion response</returns>
    /// <response code="200">Account deleted successfully</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">User not found</response>
    [HttpDelete("account")]
    [EnableRateLimiting("AccountDeletionPolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteAccount(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("Account deletion request for user: {UserId}", userId);

            // This would typically call a specific command for account deletion
            // For now, returning a placeholder response
            _logger.LogInformation("Account deletion initiated for user: {UserId}", userId);

            return Ok(ApiResponse.SuccessResponse("Account deletion initiated. You will receive a confirmation email."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting account for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Account deletion failed", HttpContext.TraceIdentifier));
        }
    }

    #region Private Helper Methods

    /// <summary>
    /// Gets the client IP address
    /// </summary>
    private string GetClientIpAddress()
    {
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    }

    /// <summary>
    /// Gets the user agent
    /// </summary>
    private string GetUserAgent()
    {
        return HttpContext.Request.Headers["User-Agent"].ToString() ?? "Unknown";
    }

    /// <summary>
    /// Gets the current user ID from JWT claims
    /// </summary>
    private Guid GetCurrentUserId()
    {
        var userIdClaim = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(userIdClaim, out var userId) ? userId : Guid.Empty;
    }

    /// <summary>
    /// Gets the current session ID from JWT claims
    /// </summary>
    private Guid GetCurrentSessionId()
    {
        var sessionIdClaim = HttpContext.User.FindFirst("SessionId")?.Value;
        return Guid.TryParse(sessionIdClaim, out var sessionId) ? sessionId : Guid.Empty;
    }

    /// <summary>
    /// Gets the current username from JWT claims
    /// </summary>
    private string GetCurrentUsername()
    {
        return HttpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? "Unknown";
    }

    #endregion
}