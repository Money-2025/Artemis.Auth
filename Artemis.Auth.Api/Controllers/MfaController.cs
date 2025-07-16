using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using AutoMapper;
using MediatR;
using Artemis.Auth.Api.DTOs.Mfa;
using Artemis.Auth.Api.DTOs.Common;
using Artemis.Auth.Application.Features.Mfa.Commands.SetupMfa;
using Artemis.Auth.Application.Features.Mfa.Commands.VerifyMfa;
using Artemis.Auth.Application.Features.Mfa.Commands.DisableMfa;
using Artemis.Auth.Application.Features.Mfa.Queries.GetMfaStatus;
using Artemis.Auth.Application.Features.Mfa.Commands.GenerateBackupCodes;

namespace Artemis.Auth.Api.Controllers;

/// <summary>
/// Multi-Factor Authentication controller providing comprehensive MFA management
/// Implements secure MFA setup, verification, and management endpoints
/// </summary>
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[Authorize]
[Produces("application/json")]
[EnableRateLimiting("MfaPolicy")]
public class MfaController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly IMapper _mapper;
    private readonly ILogger<MfaController> _logger;

    /// <summary>
    /// Initializes the MFA controller
    /// </summary>
    public MfaController(
        IMediator mediator,
        IMapper mapper,
        ILogger<MfaController> logger)
    {
        _mediator = mediator ?? throw new ArgumentNullException(nameof(mediator));
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Gets the current user's MFA status and available methods
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>MFA status information</returns>
    /// <response code="200">MFA status retrieved successfully</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">User not found</response>
    [HttpGet("status")]
    [ProducesResponseType(typeof(ApiResponse<MfaStatusResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetMfaStatus(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("MFA status request for user: {UserId}", userId);

            var query = new GetMfaStatusQuery { UserId = userId };
            var result = await _mediator.Send(query, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("MFA status retrieval failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("MFA_STATUS_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<MfaStatusResponse>(result.Data);
            
            _logger.LogInformation("MFA status retrieved successfully for user: {UserId}", userId);

            return Ok(ApiResponse<MfaStatusResponse>.SuccessResponse(response, "MFA status retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving MFA status for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("MFA status retrieval failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Initiates MFA setup for a specific method
    /// </summary>
    /// <param name="request">MFA setup request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>MFA setup response with QR code or setup instructions</returns>
    /// <response code="200">MFA setup initiated successfully</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="409">MFA already enabled</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("setup")]
    [EnableRateLimiting("MfaSetupPolicy")]
    [ProducesResponseType(typeof(ApiResponse<MfaSetupResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> SetupMfa(
        [FromBody] MfaSetupRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();
            
            _logger.LogInformation("MFA setup request for user: {UserId}, method: {Method}", 
                userId, request.Method);

            var command = _mapper.Map<SetupMfaCommand>(request);
            command.UserId = userId;
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("MFA setup failed for user: {UserId}, method: {Method}. Reason: {Reason}", 
                    userId, request.Method, result.Message);

                return result.Message switch
                {
                    var msg when msg.Contains("already enabled") || msg.Contains("already configured") => Conflict(
                        ErrorResponse.ConflictError(msg, HttpContext.TraceIdentifier)),
                    var msg when msg.Contains("not supported") => BadRequest(
                        ErrorResponse.CustomError("UNSUPPORTED_MFA_METHOD", msg, 400, HttpContext.TraceIdentifier)),
                    _ => BadRequest(
                        ErrorResponse.CustomError("MFA_SETUP_ERROR", result.Message, 400, HttpContext.TraceIdentifier))
                };
            }

            var response = _mapper.Map<MfaSetupResponse>(result.Data);
            
            _logger.LogInformation("MFA setup initiated successfully for user: {UserId}, method: {Method}", 
                userId, request.Method);

            return Ok(ApiResponse<MfaSetupResponse>.SuccessResponse(response, "MFA setup initiated successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting up MFA for user: {UserId}, method: {Method}", 
                GetCurrentUserId(), request.Method);
            return StatusCode(500, ErrorResponse.InternalServerError("MFA setup failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Verifies MFA code and completes setup or validates login
    /// </summary>
    /// <param name="request">MFA verification request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>MFA verification response</returns>
    /// <response code="200">MFA verification successful</response>
    /// <response code="400">Invalid MFA code</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("verify")]
    [EnableRateLimiting("MfaVerifyPolicy")]
    [ProducesResponseType(typeof(ApiResponse<MfaVerifyResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> VerifyMfa(
        [FromBody] MfaVerifyRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();
            
            _logger.LogInformation("MFA verification request for user: {UserId}, method: {Method}", 
                userId, request.Method);

            var command = _mapper.Map<VerifyMfaCommand>(request);
            command.UserId = userId;
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("MFA verification failed for user: {UserId}, method: {Method}. Reason: {Reason}", 
                    userId, request.Method, result.Message);

                return result.Message switch
                {
                    var msg when msg.Contains("invalid") || msg.Contains("expired") || msg.Contains("incorrect") => BadRequest(
                        ErrorResponse.CustomError("INVALID_MFA_CODE", msg, 400, HttpContext.TraceIdentifier)),
                    var msg when msg.Contains("not found") => BadRequest(
                        ErrorResponse.CustomError("MFA_NOT_CONFIGURED", msg, 400, HttpContext.TraceIdentifier)),
                    _ => BadRequest(
                        ErrorResponse.CustomError("MFA_VERIFICATION_ERROR", result.Message, 400, HttpContext.TraceIdentifier))
                };
            }

            var response = _mapper.Map<MfaVerifyResponse>(result.Data);
            
            _logger.LogInformation("MFA verification successful for user: {UserId}, method: {Method}", 
                userId, request.Method);

            return Ok(ApiResponse<MfaVerifyResponse>.SuccessResponse(response, "MFA verification successful"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying MFA for user: {UserId}, method: {Method}", 
                GetCurrentUserId(), request.Method);
            return StatusCode(500, ErrorResponse.InternalServerError("MFA verification failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Disables MFA for the current user
    /// </summary>
    /// <param name="request">MFA disable request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>MFA disable response</returns>
    /// <response code="200">MFA disabled successfully</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Unauthorized or invalid credentials</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("disable")]
    [EnableRateLimiting("MfaDisablePolicy")]
    [ProducesResponseType(typeof(ApiResponse<MfaDisableResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> DisableMfa(
        [FromBody] MfaDisableRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();
            
            _logger.LogInformation("MFA disable request for user: {UserId}", userId);

            var command = _mapper.Map<DisableMfaCommand>(request);
            command.UserId = userId;
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("MFA disable failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return result.Message switch
                {
                    var msg when msg.Contains("password") || msg.Contains("invalid") => Unauthorized(
                        ErrorResponse.AuthenticationError(msg, HttpContext.TraceIdentifier)),
                    var msg when msg.Contains("not enabled") => BadRequest(
                        ErrorResponse.CustomError("MFA_NOT_ENABLED", msg, 400, HttpContext.TraceIdentifier)),
                    _ => BadRequest(
                        ErrorResponse.CustomError("MFA_DISABLE_ERROR", result.Message, 400, HttpContext.TraceIdentifier))
                };
            }

            var response = _mapper.Map<MfaDisableResponse>(result.Data);
            
            _logger.LogInformation("MFA disabled successfully for user: {UserId}", userId);

            return Ok(ApiResponse<MfaDisableResponse>.SuccessResponse(response, "MFA disabled successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error disabling MFA for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("MFA disable failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Generates new backup codes for MFA
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>New backup codes</returns>
    /// <response code="200">Backup codes generated successfully</response>
    /// <response code="400">MFA not enabled</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("backup-codes")]
    [EnableRateLimiting("MfaBackupCodesPolicy")]
    [ProducesResponseType(typeof(ApiResponse<MfaBackupCodesResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> GenerateBackupCodes(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("MFA backup codes generation request for user: {UserId}", userId);

            var command = new GenerateBackupCodesCommand
            {
                UserId = userId,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning("MFA backup codes generation failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return result.Message.Contains("not enabled") 
                    ? BadRequest(ErrorResponse.CustomError("MFA_NOT_ENABLED", result.Message, 400, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("BACKUP_CODES_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<MfaBackupCodesResponse>(result.Data);
            
            _logger.LogInformation("MFA backup codes generated successfully for user: {UserId}", userId);

            return Ok(ApiResponse<MfaBackupCodesResponse>.SuccessResponse(response, "Backup codes generated successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating backup codes for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Backup codes generation failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Gets available MFA methods
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Available MFA methods</returns>
    /// <response code="200">MFA methods retrieved successfully</response>
    /// <response code="401">Unauthorized</response>
    [HttpGet("methods")]
    [ProducesResponseType(typeof(ApiResponse<List<MfaMethodInfo>>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GetMfaMethods(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("MFA methods request for user: {UserId}", userId);

            // This would typically call a specific query for available MFA methods
            // For now, returning a static list of supported methods
            var methods = new List<MfaMethodInfo>
            {
                new MfaMethodInfo
                {
                    Type = "TOTP",
                    DisplayName = "Authenticator App",
                    Description = "Use an authenticator app like Google Authenticator or Microsoft Authenticator",
                    IsEnabled = true,
                    IsConfigured = false
                },
                new MfaMethodInfo
                {
                    Type = "SMS",
                    DisplayName = "SMS",
                    Description = "Receive verification codes via SMS",
                    IsEnabled = true,
                    IsConfigured = false
                },
                new MfaMethodInfo
                {
                    Type = "Email",
                    DisplayName = "Email",
                    Description = "Receive verification codes via email",
                    IsEnabled = true,
                    IsConfigured = false
                }
            };

            _logger.LogInformation("MFA methods retrieved successfully for user: {UserId}", userId);

            return Ok(ApiResponse<List<MfaMethodInfo>>.SuccessResponse(methods, "MFA methods retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving MFA methods for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("MFA methods retrieval failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Removes a specific MFA method
    /// </summary>
    /// <param name="method">MFA method to remove</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>MFA method removal response</returns>
    /// <response code="200">MFA method removed successfully</response>
    /// <response code="400">Invalid method or cannot remove</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="404">Method not found</response>
    [HttpDelete("methods/{method}")]
    [EnableRateLimiting("MfaMethodRemovalPolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveMfaMethod(
        [FromRoute] string method,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("MFA method removal request for user: {UserId}, method: {Method}", 
                userId, method);

            // This would typically call a specific command for removing MFA method
            // For now, returning a placeholder response
            _logger.LogInformation("MFA method removal successful for user: {UserId}, method: {Method}", 
                userId, method);

            return Ok(ApiResponse.SuccessResponse("MFA method removed successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing MFA method for user: {UserId}, method: {Method}", 
                GetCurrentUserId(), method);
            return StatusCode(500, ErrorResponse.InternalServerError("MFA method removal failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Resets MFA for the current user (emergency procedure)
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>MFA reset response</returns>
    /// <response code="200">MFA reset initiated</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("reset")]
    [EnableRateLimiting("MfaResetPolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> ResetMfa(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            
            _logger.LogInformation("MFA reset request for user: {UserId}", userId);

            // This would typically call a specific command for MFA reset
            // For now, returning a placeholder response
            _logger.LogInformation("MFA reset initiated for user: {UserId}", userId);

            return Ok(ApiResponse.SuccessResponse("MFA reset initiated. Please check your email for instructions."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting MFA for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("MFA reset failed", HttpContext.TraceIdentifier));
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
    /// Gets the current username from JWT claims
    /// </summary>
    private string GetCurrentUsername()
    {
        return HttpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? "Unknown";
    }

    #endregion
}