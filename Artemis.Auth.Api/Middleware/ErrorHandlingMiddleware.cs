using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Artemis.Auth.Api.DTOs.Common;
using Artemis.Auth.Application.Common.Exceptions;

namespace Artemis.Auth.Api.Middleware;

/// <summary>
/// Global error handling middleware for consistent error responses
/// </summary>
public class ErrorHandlingMiddleware : IMiddleware
{
    private readonly ILogger<ErrorHandlingMiddleware> _logger;
    private readonly IWebHostEnvironment _environment;

    /// <summary>
    /// Initializes the error handling middleware
    /// </summary>
    public ErrorHandlingMiddleware(
        ILogger<ErrorHandlingMiddleware> logger,
        IWebHostEnvironment environment)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
    }

    /// <summary>
    /// Handles errors and returns consistent error responses
    /// If there is no exception, it simply calls the next middleware in the pipeline
    /// </summary>
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
    }

    /// <summary>
    /// Handles exceptions and creates appropriate error responses
    /// </summary>
    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        var traceId = context.TraceIdentifier;
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        
        // Log the exception with context
        _logger.LogError(exception, 
            "Error occurred. TraceId: {TraceId}, IP: {IpAddress}, Path: {Path}, Method: {Method}",
            traceId, ipAddress, context.Request.Path, context.Request.Method);

        var errorResponse = exception switch
        {
            ValidationException validationEx => CreateValidationErrorResponse(validationEx, traceId),
            UnauthorizedException unauthorizedEx => CreateUnauthorizedErrorResponse(unauthorizedEx, traceId),
            ForbiddenException forbiddenEx => CreateForbiddenErrorResponse(forbiddenEx, traceId),
            NotFoundException notFoundEx => CreateNotFoundErrorResponse(notFoundEx, traceId),
            ConflictException conflictEx => CreateConflictErrorResponse(conflictEx, traceId),
            BusinessRuleException businessEx => CreateBusinessRuleErrorResponse(businessEx, traceId),
            RateLimitException rateLimitEx => CreateRateLimitErrorResponse(rateLimitEx, traceId),
            _ => CreateInternalServerErrorResponse(exception, traceId)
        };
        
        // TODO: potential exceptions we might want to handle specifically:
        /*
           
           | Exception Type                       | Returned Code                  | HTTP Status                | When to Use (Scenario)                                                                                   | Typical Client Action / UX                                        | Possible Meta Fields (examples)                                |
           |-------------------------------------|--------------------------------|----------------------------|-----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|----------------------------------------------------------------|
           | `AuthenticationFailedException`     | `AUTHENTICATION_FAILED`        | 401 Unauthorized           | Login attempt with invalid credentials (username/password mismatch).                                     | Show generic login error; increment local retry counter.          | `attemptCount`, `lockoutRemainingSeconds`                      |
           | `AccountLockedException`            | `ACCOUNT_LOCKED`               | 423 Locked *(or 403)*      | Account locked due to repeated failures or admin action.                                                 | Inform user; disable login form until unlock time.                | `unlockAtUtc`, `lockReason`                                    |
           | `AccountDisabledException`          | `ACCOUNT_DISABLED`             | 403 Forbidden              | Account disabled (soft delete / suspended).                                                              | Show support contact info.                                        | `disabledSinceUtc`, `actor`                                    |
           | `EmailNotVerifiedException`         | `EMAIL_NOT_VERIFIED`           | 403 Forbidden              | Resource requires verified email but user’s email is still unverified.                                   | Prompt “Verify email” with resend option.                         | `email`, `verificationSentAtUtc`                               |
           | `TwoFactorRequiredException`        | `TWO_FACTOR_REQUIRED`          | 401 Unauthorized           | After primary auth; second factor pending.                                                               | Redirect to 2FA entry screen.                                     | `methods` (e.g. `["TOTP","Email"]`)                            |
           | `TwoFactorFailedException`          | `TWO_FACTOR_FAILED`            | 401 Unauthorized           | Provided 2FA code/token invalid.                                                                         | Show error; allow limited retries; warn on final attempt.         | `remainingAttempts`                                            |
           | `PasswordPolicyViolationException`  | `PASSWORD_POLICY_VIOLATION`    | 400 Bad Request            | Password change/reset fails complexity/history policy.                                                   | Highlight failed rules in UI.                                     | `failedRules` (array), `minLength`, `requiresSymbols`          |
           | `CredentialReuseException`          | `CREDENTIAL_REUSE_NOT_ALLOWED` | 400 Bad Request            | New password equals one of recently used passwords.                                                      | Ask for a different password.                                     | `lastPasswordChangeUtc`, `historyDepth`                        |
           | `TokenExpiredException`             | `TOKEN_EXPIRED`                | 401 Unauthorized           | Access token expired (but refresh token might still be valid).                                           | Attempt silent refresh; if fails, force re-login.                 | `expiredAtUtc`                                                 |
           | `InvalidTokenException`             | `INVALID_TOKEN`                | 401 Unauthorized           | Malformed / signature-invalid / unsupported JWT.                                                         | Force full re-authentication.                                     | `tokenIssue` (e.g. `SignatureInvalid`)                        |
           | `RefreshTokenExpiredException`      | `REFRESH_TOKEN_EXPIRED`        | 401 Unauthorized           | Refresh token lifetime exceeded.                                                                         | Clear session; redirect to login.                                 | `expiredAtUtc`                                                 |
           | `RefreshTokenRevokedException`      | `REFRESH_TOKEN_REVOKED`        | 401 Unauthorized           | Refresh token explicitly revoked (compromise, logout-all).                                               | Clear session; show security notice.                              | `revokedAtUtc`, `revocationReason`                             |
           | `InsufficientScopeException`        | `INSUFFICIENT_SCOPE`           | 403 Forbidden              | OAuth2 / API scope(s) required not provided.                                                             | Prompt for re-auth with expanded scopes.                          | `requiredScopes`, `providedScopes`                             |
           | `PermissionDeniedException`         | `PERMISSION_DENIED`            | 403 Forbidden              | More granular than generic forbidden; specific permission missing.                                       | Show missing permission; optionally request elevation.            | `requiredPermission`, `userPermissions`                       |
           | `RoleAssignmentConflictException`   | `ROLE_ASSIGNMENT_CONFLICT`     | 409 Conflict               | Attempt to assign duplicate or mutually exclusive roles.                                                 | Reject form; show conflicting roles.                              | `role`, `conflictingRoles`                                     |
           | `SessionNotFoundException`          | `SESSION_NOT_FOUND`            | 401 Unauthorized           | Provided session identifier doesn’t map to active session.                                               | Remove stale cookies; force login.                                | `sessionId`                                                    |
           | `SessionExpiredException`           | `SESSION_EXPIRED`              | 401 Unauthorized           | Session TTL reached.                                                                                     | Transparent re-auth flow (if refresh) or login screen.            | `expiredAtUtc`                                                 |
           | `SessionRevokedException`           | `SESSION_REVOKED`              | 401 Unauthorized           | Server invalidated session (admin action, security event).                                               | Inform user; force login; security notice.                        | `revokedAtUtc`, `reason`                                       |
           | `InvalidStateTransitionException`   | `INVALID_STATE_TRANSITION`     | 409 Conflict               | Domain aggregate state change not permitted (e.g., verifying already verified email).                    | Show contextual message; disable invalid action UI.               | `currentState`, `attemptedTransition`                          |
           | `PublicKeyNotFoundException`        | `KEY_NOT_FOUND`                | 500 Internal Server Error  | JWT `kid` not found in keystore (rotation mismatch).                                                      | Retry after short delay; escalate if recurring.                   | `keyId`                                                        |
           | `KeyRotationInProgressException`    | `KEY_ROTATION_IN_PROGRESS`     | 503 Service Unavailable    | Temporary signing/validation gap during key rotation window.                                             | Retry after `Retry-After`.                                        | `expectedRetrySeconds`                                         |
           | `ExternalProviderAuthFailedException` | `EXTERNAL_PROVIDER_AUTH_FAILED` | 401 Unauthorized         | Social / SSO provider returned error (invalid code, mismatch).                                           | Restart external login flow; show provider error summary.         | `provider`, `providerError`                                    |
           | `ExternalAccountLinkExistsException` | `EXTERNAL_LINK_ALREADY_EXISTS` | 409 Conflict              | Linking an external provider already linked to another user.                                             | Offer account recovery / unlink instructions.                     | `provider`, `externalUserId`                                   |
           | `MfaEnrollmentRequiredException`    | `MFA_ENROLLMENT_REQUIRED`      | 403 Forbidden              | Policy enforces MFA but user not yet enrolled.                                                           | Redirect to MFA enrollment wizard.                                | `policyId`, `allowedMethods`                                   |
           | `DeviceVerificationRequiredException` | `DEVICE_VERIFICATION_REQUIRED` | 401 Unauthorized         | New device detected; device trust verification step pending.                                             | Show device verification step.                                    | `deviceId`, `challengeIssuedAtUtc`                             |
           | `DeviceVerificationFailedException` | `DEVICE_VERIFICATION_FAILED`   | 401 Unauthorized           | Provided device verification token/code invalid.                                                         | Allow limited retries; escalate lock if repeated.                 | `remainingAttempts`                                            |
           | `ApiKeyNotFoundException`           | `API_KEY_NOT_FOUND`            | 401 Unauthorized           | Supplied API key does not exist.                                                                        | Reject; instruct to generate a new key.                           | `apiKeyId`                                                     |
           | `ApiKeyRevokedException`            | `API_KEY_REVOKED`              | 401 Unauthorized           | API key revoked or disabled.                                                                             | Prompt regeneration; audit alert.                                 | `apiKeyId`, `revokedAtUtc`                                     |
           | `ApiKeyExpiredException`            | `API_KEY_EXPIRED`              | 401 Unauthorized           | API key passed its validity period.                                                                      | Regenerate key; update integrations.                              | `apiKeyId`, `expiredAtUtc`                                     |
           | `RateLimitPerUserException`         | `USER_RATE_LIMIT_EXCEEDED`     | 429 Too Many Requests      | User-based quota exceeded.                                                                               | Backoff and retry after window.                                   | `retryAfter`, `limit`, `window`, `userId`                      |
           | `RateLimitPerIpException`           | `IP_RATE_LIMIT_EXCEEDED`       | 429 Too Many Requests      | IP-based throttling triggered (possible abuse).                                                          | Backoff; possibly show captcha.                                   | `retryAfter`, `limit`, `window`, `ip`                          |
           | `SecurityPolicyViolationException`  | `SECURITY_POLICY_VIOLATION`    | 400 Bad Request            | General security policy breach (e.g., disallowed password pattern variant beyond standard policy).       | Inform user; block action.                                        | `policyId`, `violationType`                                    |
           | `AuditIntegrityException`           | `AUDIT_INTEGRITY_ERROR`        | 500 Internal Server Error  | Audit trail write/consistency failure detected.                                                          | Retry or alert admin; trigger monitoring.                         | `operationId`, `entity`                                        |
           | `EncryptionFailureException`        | `ENCRYPTION_FAILURE`           | 500 Internal Server Error  | Cryptographic operation failed (encryption/decryption/signing).                                          | Retry once; escalate if persistent.                               | `operation`, `algorithm`                                       |
           | `HashingFailureException`           | `HASHING_FAILURE`              | 500 Internal Server Error  | Password/secret hashing process failed.                                                                  | Abort; log; security alert.                                       | `algorithm`, `iterationCount`                                  |
           | `IntegrityCheckFailedException`     | `INTEGRITY_CHECK_FAILED`       | 400 Bad Request            | Payload / nonce / anti-replay integrity verification failure.                                           | Force new request; maybe re-init handshake.                       | `checkType`, `reason`                                          |
           | `ReplayAttackDetectedException`     | `REPLAY_ATTACK_DETECTED`       | 409 Conflict *(or 400)*    | Nonce or timestamp reused; potential replay attack.                                                      | Invalidate session; strong warning; log security event.           | `nonce`, `firstSeenAtUtc`                                      |
           | `BruteForceSuspectedException`      | `BRUTE_FORCE_SUSPECTED`        | 429 Too Many Requests      | Heuristic triggered by rapid failed attempts from same source.                                           | Force cooldown; maybe captcha.                                    | `cooldownSeconds`, `ip`                                        |
           | `GeoRestrictionException`           | `GEO_RESTRICTED`               | 403 Forbidden              | Access blocked due to geographic policy restrictions.                                                    | Show region restriction notice.                                   | `countryCode`, `policyId`                                      |
           | `IpRiskBlockedException`            | `IP_RISK_BLOCKED`              | 403 Forbidden              | IP flagged by risk engine (TOR, blacklist).                                                              | Deny; offer appeal/contact.                                       | `ip`, `riskScore`                                              |
           
         */

        context.Response.StatusCode = errorResponse.StatusCode;
        context.Response.ContentType = "application/json";

        var jsonResponse = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        });

        await context.Response.WriteAsync(jsonResponse);
    }

    /// <summary>
    /// Creates validation error response
    /// </summary>
    private ErrorResponse CreateValidationErrorResponse(ValidationException exception, string traceId)
    {
        var validationErrors = exception.ValidationErrors?.ToDictionary(
            kvp => kvp.Key, 
            kvp => kvp.Value.ToArray()
        );

        return new ErrorResponse
        {
            Code = "VALIDATION_ERROR",
            Message = "One or more validation errors occurred",
            Details = exception.Message,
            StatusCode = (int)HttpStatusCode.BadRequest,
            TraceId = traceId,
            ValidationErrors = validationErrors,
            Meta = new Dictionary<string, object>
            {
                ["ValidationFailures"] = exception.ValidationErrors?.Count ?? 0
            }
        };
    }

    /// <summary>
    /// Creates unauthorized error response
    /// </summary>
    private ErrorResponse CreateUnauthorizedErrorResponse(UnauthorizedException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "UNAUTHORIZED",
            Message = exception.Message,
            Details = "Authentication is required to access this resource",
            StatusCode = (int)HttpStatusCode.Unauthorized,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["RequiredAuthentication"] = true
            }
        };
    }

    /// <summary>
    /// Creates forbidden error response
    /// </summary>
    private ErrorResponse CreateForbiddenErrorResponse(ForbiddenException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "FORBIDDEN",
            Message = exception.Message,
            Details = "You don't have permission to access this resource",
            StatusCode = (int)HttpStatusCode.Forbidden,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["RequiredPermission"] = exception.RequiredPermission ?? "Unknown"
            }
        };
    }

    /// <summary>
    /// Creates not found error response
    /// </summary>
    private ErrorResponse CreateNotFoundErrorResponse(NotFoundException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "NOT_FOUND",
            Message = exception.Message,
            Details = "The requested resource was not found",
            StatusCode = (int)HttpStatusCode.NotFound,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["ResourceType"] = exception.EntityName ?? "Unknown",
                ["ResourceId"] = exception.EntityId?.ToString() ?? "Unknown"
            }
        };
    }

    /// <summary>
    /// Creates conflict error response
    /// </summary>
    private ErrorResponse CreateConflictErrorResponse(ConflictException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "CONFLICT",
            Message = exception.Message,
            Details = "The request conflicts with the current state of the resource",
            StatusCode = (int)HttpStatusCode.Conflict,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["ConflictType"] = exception.ConflictType ?? "Unknown"
            }
        };
    }

    /// <summary>
    /// Creates business rule error response
    /// </summary>
    private ErrorResponse CreateBusinessRuleErrorResponse(BusinessRuleException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "BUSINESS_RULE_VIOLATION",
            Message = exception.Message,
            Details = exception.Details,
            StatusCode = (int)HttpStatusCode.BadRequest,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["RuleType"] = exception.RuleType ?? "Unknown"
            }
        };
    }

    /// <summary>
    /// Creates rate limit error response
    /// </summary>
    private ErrorResponse CreateRateLimitErrorResponse(RateLimitException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "RATE_LIMIT_EXCEEDED",
            Message = exception.Message,
            Details = "Too many requests. Please try again later.",
            StatusCode = (int)HttpStatusCode.TooManyRequests,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["RetryAfter"] = exception.RetryAfter?.TotalSeconds ?? 60,
                ["Limit"] = exception.Limit,
                ["Window"] = exception.Window?.TotalSeconds ?? 60
            }
        };
    }

    /// <summary>
    /// Creates internal server error response
    /// </summary>
    private ErrorResponse CreateInternalServerErrorResponse(Exception exception, string traceId)
    {
        var message = _environment.IsDevelopment() 
            ? exception.Message 
            : "An internal server error occurred";
            
        var details = _environment.IsDevelopment() 
            ? exception.ToString() 
            : "Please contact support if the problem persists";

        return new ErrorResponse
        {
            Code = "INTERNAL_SERVER_ERROR",
            Message = message,
            Details = details,
            StatusCode = (int)HttpStatusCode.InternalServerError,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["ExceptionType"] = exception.GetType().Name,
                ["IsDevelopment"] = _environment.IsDevelopment()
            }
        };
    }
}

/// <summary>
/// Rate limit exception for rate limiting middleware
/// </summary>
public class RateLimitException : Exception
{
    public int Limit { get; }
    public TimeSpan? Window { get; }
    public TimeSpan? RetryAfter { get; }

    public RateLimitException(string message, int limit, TimeSpan? window = null, TimeSpan? retryAfter = null) 
        : base(message)
    {
        Limit = limit;
        Window = window;
        RetryAfter = retryAfter;
    }
}