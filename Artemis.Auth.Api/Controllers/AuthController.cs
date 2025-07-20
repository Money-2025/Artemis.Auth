using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using AutoMapper;
using MediatR;
using Artemis.Auth.Api.DTOs.Authentication;
using Artemis.Auth.Api.DTOs.Common;
using Artemis.Auth.Application.Features.Authentication.Commands.Login;
using Artemis.Auth.Application.Features.Authentication.Commands.RegisterUser;
using Artemis.Auth.Application.Features.Authentication.Commands.RefreshToken;
using Artemis.Auth.Application.Features.Authentication.Commands.ForgotPassword;
using Artemis.Auth.Application.Features.Authentication.Commands.ResetPassword;
using Artemis.Auth.Application.Features.Authentication.Commands.VerifyEmail;
using Artemis.Auth.Application.Features.Authentication.Commands.Logout;
using Artemis.Auth.Application.Features.Authentication.Commands.ResendVerification;

namespace Artemis.Auth.Api.Controllers;

/// <summary>
/// Authentication controller providing comprehensive authentication endpoints
/// Implements secure authentication with rate limiting, validation, and comprehensive error handling
/// </summary>
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[Produces("application/json")]
[EnableRateLimiting("AuthPolicy")]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly IMapper _mapper;
    private readonly ILogger<AuthController> _logger;

    /// <summary>
    /// Initializes the authentication controller
    /// </summary>
    public AuthController(
        IMediator mediator,
        IMapper mapper,
        ILogger<AuthController> logger)
    {
        _mediator = mediator ?? throw new ArgumentNullException(nameof(mediator));
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Authenticates a user and returns JWT tokens
    /// </summary>
    /// <param name="request">Login credentials</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Login response with JWT tokens and user information</returns>
    /// <response code="200">Login successful</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Authentication failed</response>
    /// <response code="423">Account locked</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting("LoginPolicy")]
    [ProducesResponseType(typeof(ApiResponse<LoginResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status423Locked)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> Login(
        [FromBody] LoginRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();

            _logger.LogInformation("Login attempt for user: {Username} from IP: {IpAddress}", 
                request.Username, request.IpAddress);

            // Map to command
            var command = _mapper.Map<LoginCommand>(request);
            
            // Execute login command
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Login failed for user: {Username}. Reason: {Reason}", 
                    request.Username, result.Message);

                return result.Message switch
                {
                    var msg when msg.Contains("locked") => StatusCode(423, 
                        ErrorResponse.CustomError("ACCOUNT_LOCKED", msg, 423, HttpContext.TraceIdentifier)),
                    var msg when msg.Contains("not found") || msg.Contains("invalid") => Unauthorized(
                        ErrorResponse.AuthenticationError(msg, HttpContext.TraceIdentifier)),
                    var msg when msg.Contains("confirmed") => BadRequest(
                        ErrorResponse.CustomError("EMAIL_NOT_CONFIRMED", msg, 400, HttpContext.TraceIdentifier)),
                    _ => BadRequest(
                        ErrorResponse.CustomError("LOGIN_FAILED", result.Message, 400, HttpContext.TraceIdentifier))
                };
            }

            // Map to response
            var response = _mapper.Map<LoginResponse>(result.Data);
            
            _logger.LogInformation("Login successful for user: {Username}", request.Username);

            return Ok(ApiResponse<LoginResponse>.SuccessResponse(response, "Login successful"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for user: {Username}", request.Username);
            return StatusCode(500, ErrorResponse.InternalServerError("Login failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Registers a new user account
    /// </summary>
    /// <param name="request">Registration information</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Registration response</returns>
    /// <response code="201">Registration successful</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="409">User already exists</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("register")]
    [AllowAnonymous]
    [EnableRateLimiting("RegisterPolicy")]
    [ProducesResponseType(typeof(ApiResponse<RegisterResponse>), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> Register(
        [FromBody] RegisterRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();

            _logger.LogInformation("Registration attempt for user: {Username}, email: {Email}", 
                request.Username, request.Email);

            // Map to command
            var command = _mapper.Map<RegisterUserCommand>(request);
            
            // Execute registration command
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Registration failed for user: {Username}. Reason: {Reason}", 
                    request.Username, result.Message);

                return result.Message switch
                {
                    var msg when msg.Contains("already exists") || msg.Contains("taken") => Conflict(
                        ErrorResponse.ConflictError(msg, HttpContext.TraceIdentifier)),
                    _ => BadRequest(
                        ErrorResponse.CustomError("REGISTRATION_FAILED", result.Message, 400, HttpContext.TraceIdentifier))
                };
            }

            // Map to response
            var response = _mapper.Map<RegisterResponse>(result.Data);
            
            _logger.LogInformation("Registration successful for user: {Username}", request.Username);

            return StatusCode(201, ApiResponse<RegisterResponse>.SuccessResponse(response, "Registration successful"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration for user: {Username}", request.Username);
            return StatusCode(500, ErrorResponse.InternalServerError("Registration failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Refreshes an expired JWT token
    /// </summary>
    /// <param name="request">Refresh token request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>New JWT tokens</returns>
    /// <response code="200">Token refresh successful</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Invalid refresh token</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("refresh")]
    [AllowAnonymous]
    [EnableRateLimiting("RefreshPolicy")]
    [ProducesResponseType(typeof(ApiResponse<LoginResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> RefreshToken(
        [FromBody] RefreshTokenRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();

            _logger.LogInformation("Token refresh attempt from IP: {IpAddress}", request.IpAddress);

            // Map to command
            var command = _mapper.Map<RefreshTokenCommand>(request);
            
            // Execute refresh command
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Token refresh failed. Reason: {Reason}", result.Message);

                return result.Message switch
                {
                    var msg when msg.Contains("invalid") || msg.Contains("expired") => Unauthorized(
                        ErrorResponse.AuthenticationError(msg, HttpContext.TraceIdentifier)),
                    _ => BadRequest(
                        ErrorResponse.CustomError("TOKEN_REFRESH_FAILED", result.Message, 400, HttpContext.TraceIdentifier))
                };
            }

            // Map to response
            var response = _mapper.Map<LoginResponse>(result.Data);
            
            _logger.LogInformation("Token refresh successful");

            return Ok(ApiResponse<LoginResponse>.SuccessResponse(response, "Token refresh successful"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token refresh");
            return StatusCode(500, ErrorResponse.InternalServerError("Token refresh failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Initiates password reset process
    /// </summary>
    /// <param name="request">Forgot password request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Password reset response</returns>
    /// <response code="200">Password reset email sent</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("forgot-password")]
    [AllowAnonymous]
    [EnableRateLimiting("ForgotPasswordPolicy")]
    [ProducesResponseType(typeof(ApiResponse<ForgotPasswordResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> ForgotPassword(
        [FromBody] ForgotPasswordRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();

            _logger.LogInformation("Password reset request for email: {Email}", request.Email);

            // Map to command
            var command = _mapper.Map<ForgotPasswordCommand>(request);
            
            // Execute forgot password command
            var result = await _mediator.Send(command, cancellationToken);

            // Always return success for security reasons (don't reveal if email exists)
            var response = new ForgotPasswordResponse
            {
                Success = true,
                Message = "If an account with this email exists, a password reset link has been sent.",
                EmailSent = result.IsSuccess
            };

            _logger.LogInformation("Password reset response sent for email: {Email}", request.Email);

            return Ok(ApiResponse<ForgotPasswordResponse>.SuccessResponse(response, response.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during password reset request for email: {Email}", request.Email);
            return StatusCode(500, ErrorResponse.InternalServerError("Password reset request failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Resets user password using reset token
    /// </summary>
    /// <param name="request">Reset password request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Password reset response</returns>
    /// <response code="200">Password reset successful</response>
    /// <response code="400">Invalid request data or token</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("reset-password")]
    [AllowAnonymous]
    [EnableRateLimiting("ResetPasswordPolicy")]
    [ProducesResponseType(typeof(ApiResponse<ResetPasswordResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> ResetPassword(
        [FromBody] ResetPasswordRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();

            _logger.LogInformation("Password reset attempt for email: {Email}", request.Email);

            // Map to command
            var command = _mapper.Map<ResetPasswordCommand>(request);
            
            // Execute reset password command
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Password reset failed for email: {Email}. Reason: {Reason}", 
                    request.Email, result.Message);

                return BadRequest(
                    ErrorResponse.CustomError("PASSWORD_RESET_FAILED", result.Message, 400, HttpContext.TraceIdentifier));
            }

            // Map to response
            var response = _mapper.Map<ResetPasswordResponse>(result.Data);
            
            _logger.LogInformation("Password reset successful for email: {Email}", request.Email);

            return Ok(ApiResponse<ResetPasswordResponse>.SuccessResponse(response, "Password reset successful"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during password reset for email: {Email}", request.Email);
            return StatusCode(500, ErrorResponse.InternalServerError("Password reset failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Handles email confirmation via GET request from email links
    /// </summary>
    /// <param name="token">JWT confirmation token from email</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>HTML response with confirmation result</returns>
    /// <response code="200">Email confirmed successfully</response>
    /// <response code="400">Invalid or expired token</response>
    [HttpGet("confirm-email")]
    [AllowAnonymous]
    [EnableRateLimiting("VerifyEmailPolicy")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ConfirmEmail(
        [FromQuery] string token,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogWarning("Email confirmation attempt with empty token");
                return BadRequest(GenerateHtmlResponse(false, "Invalid confirmation link",
                    "The confirmation link is invalid or incomplete."));
            }

            var command = new VerifyEmailCommand
            {
                Token = token,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };

            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Email confirmation failed. Reason: {Reason}", result.Message);
                return BadRequest(GenerateHtmlResponse(false, "Confirmation Failed", result.Message));
            }

            _logger.LogInformation("Email confirmation successful for {Email}", result.Data?.Email);

            return Ok(GenerateHtmlResponse(true, "Email Confirmed!",
                "Your email address has been successfully verified. You can now close this window."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during email confirmation via GET");
            return StatusCode(500, GenerateHtmlResponse(false, "Error",
                "An unexpected error occurred while confirming your email."));
        }
    }

    /// <summary>
    /// Generates HTML response for email confirmation
    /// </summary>
    /// <param name="success">Whether the operation was successful</param>
    /// <param name="title">Page title</param>
    /// <param name="message">Message to display</param>
    /// <returns>HTML content</returns>
    private string GenerateHtmlResponse(bool success, string title, string message)
    {
        var statusColor = success ? "#28a745" : "#dc3545";
        var icon = success ? "✅" : "❌";

        return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>{title} - Artemis Auth</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{ 
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
            margin: 1rem;
        }}
        .icon {{ 
            font-size: 3rem;
            margin-bottom: 1rem;
        }}
        .title {{ 
            color: {statusColor};
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }}
        .message {{ 
            color: #666;
            font-size: 1rem;
            line-height: 1.5;
            margin-bottom: 1.5rem;
        }}
        .footer {{ 
            color: #999;
            font-size: 0.9rem;
            border-top: 1px solid #eee;
            padding-top: 1rem;
            margin-top: 1rem;
        }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""icon"">{icon}</div>
        <h1 class=""title"">{title}</h1>
        <p class=""message"">{message}</p>
        <div class=""footer"">
            <strong>Artemis Auth</strong><br>
            Secure Authentication Service
        </div>
    </div>
</body>
</html>";
    }

    /// <summary>
    /// Logs out user and invalidates tokens
    /// </summary>
    /// <param name="request">Logout request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Logout response</returns>
    /// <response code="200">Logout successful</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Unauthorized</response>
    [HttpPost("logout")]
    [Authorize]
    [EnableRateLimiting("LogoutPolicy")]
    [ProducesResponseType(typeof(ApiResponse<LogoutResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Logout(
        [FromBody] LogoutRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Enrich request with client information
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();

            var userId = GetCurrentUserId();
            
            _logger.LogInformation("Logout attempt for user: {UserId}", userId);

            // Map to command
            var command = _mapper.Map<LogoutCommand>(request);
            command.UserId = userId;
            
            // Execute logout command
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Logout failed for user: {UserId}. Reason: {Reason}", 
                    userId, result.Message);

                return BadRequest(
                    ErrorResponse.CustomError("LOGOUT_FAILED", result.Message, 400, HttpContext.TraceIdentifier));
            }

            // Map to response
            var response = _mapper.Map<LogoutResponse>(result.Data);
            
            _logger.LogInformation("Logout successful for user: {UserId}", userId);

            return Ok(ApiResponse<LogoutResponse>.SuccessResponse(response, "Logout successful"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout for user: {UserId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Logout failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Resends email verification
    /// </summary>
    /// <param name="email">Email address</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Email resend response</returns>
    /// <response code="200">Verification email sent</response>
    /// <response code="400">Invalid email</response>
    /// <response code="429">Rate limit exceeded</response>
    [HttpPost("resend-verification")]
    [AllowAnonymous]
    [EnableRateLimiting("ResendVerificationPolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> ResendVerificationEmail(
        [FromBody] ResendVerificationRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Resend verification email request for: {Email}", request.Email);

            // Create a resend verification command
            var command = new ResendVerificationCommand 
            { 
                Email = request.Email,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };

            // Execute the command
            var result = await _mediator.Send(command, cancellationToken);

            // Always return success for security reasons (don't reveal if email exists)
            var response = new
            {
                Success = true,
                Message = "If an account with this email exists and is not verified, a verification email has been sent.",
                EmailSent = result.IsSuccess
            };

            _logger.LogInformation("Resend verification email response sent for: {Email}", request.Email);

            return Ok(ApiResponse.SuccessResponse(response.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during resend verification email for: {Email}", request.Email);
            return StatusCode(500, ErrorResponse.InternalServerError("Resend verification failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Validates JWT token
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token validation response</returns>
    /// <response code="200">Token is valid</response>
    /// <response code="401">Invalid token</response>
    [HttpGet("validate")]
    [Authorize]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> ValidateToken(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            var username = GetCurrentUsername();

            _logger.LogInformation("Token validation for user: {UserId} ({Username})", userId, username);

            var response = new
            {
                Valid = true,
                UserId = userId,
                Username = username,
                Claims = GetUserClaims()
            };

            return Ok(ApiResponse.SuccessResponse("Token is valid"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token validation");
            return StatusCode(500, ErrorResponse.InternalServerError("Token validation failed", HttpContext.TraceIdentifier));
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

    /// <summary>
    /// Gets all user claims
    /// </summary>
    private Dictionary<string, string> GetUserClaims()
    {
        return HttpContext.User.Claims.ToDictionary(c => c.Type, c => c.Value);
    }

    #endregion
}