using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Infrastructure.Common;

/// <summary>
/// Email Configuration: Contains all email service settings for SMTP and email delivery
/// Implements validation attributes to ensure secure configuration
/// Supports Gmail SMTP and other SMTP providers with secure credentials management
/// </summary>
public class EmailConfiguration
{
    /// <summary>
    /// Email service provider type
    /// Currently supports SMTP (Gmail, Outlook, etc.)
    /// Can be extended for cloud providers (SendGrid, AWS SES, etc.)
    /// </summary>
    [Required]
    public string Provider { get; set; } = "SMTP";

    /// <summary>
    /// SMTP server hostname
    /// Gmail: smtp.gmail.com
    /// Outlook: smtp-mail.outlook.com
    /// Yahoo: smtp.mail.yahoo.com
    /// </summary>
    [Required]
    [MinLength(1, ErrorMessage = "SMTP Host is required")]
    public string SmtpHost { get; set; } = "smtp.gmail.com";

    /// <summary>
    /// SMTP server port number
    /// Gmail: 587 (TLS) or 465 (SSL)
    /// Standard: 25 (unencrypted), 587 (TLS), 465 (SSL)
    /// </summary>
    [Range(1, 65535, ErrorMessage = "SMTP Port must be between 1 and 65535")]
    public int SmtpPort { get; set; } = 587;

    /// <summary>
    /// Enable SSL/TLS encryption
    /// Should always be true for production and Gmail
    /// Gmail requires SSL/TLS for security
    /// </summary>
    public bool EnableSsl { get; set; } = true;

    /// <summary>
    /// SMTP authentication username
    /// For Gmail: your full email address (e.g., yourapp@gmail.com)
    /// Should be stored securely in appsettings or environment variables
    /// </summary>
    [Required]
    [EmailAddress(ErrorMessage = "SMTP Username must be a valid email address")]
    public string SmtpUsername { get; set; } = string.Empty;

    /// <summary>
    /// SMTP authentication password
    /// For Gmail: Use App Password, not your regular password
    /// CRITICAL: Never store in code, use appsettings.json or environment variables
    /// </summary>
    [Required]
    [MinLength(8, ErrorMessage = "SMTP Password must be at least 8 characters")]
    public string SmtpPassword { get; set; } = string.Empty;

    /// <summary>
    /// Default sender email address
    /// Must be the same as SmtpUsername for Gmail
    /// Used as "From" address in all outgoing emails
    /// </summary>
    [Required]
    [EmailAddress(ErrorMessage = "From Email must be a valid email address")]
    public string FromEmail { get; set; } = string.Empty;

    /// <summary>
    /// Default sender display name
    /// Appears as the sender name in email clients
    /// Should be your application or company name
    /// </summary>
    [Required]
    [MinLength(1, ErrorMessage = "From Name is required")]
    public string FromName { get; set; } = "Artemis Auth";

    /// <summary>
    /// Reply-to email address
    /// Where users should send replies
    /// Can be different from FromEmail for organizational purposes
    /// </summary>
    [EmailAddress(ErrorMessage = "Reply To Email must be a valid email address")]
    public string? ReplyToEmail { get; set; }

    /// <summary>
    /// Connection timeout in seconds
    /// How long to wait for SMTP connection
    /// Gmail typically responds quickly, but allow for network delays
    /// </summary>
    [Range(5, 300, ErrorMessage = "Connection timeout must be between 5 and 300 seconds")]
    public int ConnectionTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Send timeout in seconds
    /// How long to wait for email sending to complete
    /// Larger emails with attachments may take longer
    /// </summary>
    [Range(10, 600, ErrorMessage = "Send timeout must be between 10 and 600 seconds")]
    public int SendTimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Maximum retry attempts for failed emails
    /// How many times to retry sending failed emails
    /// Prevents infinite retry loops
    /// </summary>
    [Range(0, 10, ErrorMessage = "Max retry attempts must be between 0 and 10")]
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Retry delay in seconds (exponential backoff base)
    /// Initial delay before first retry
    /// Subsequent delays increase exponentially
    /// </summary>
    [Range(1, 300, ErrorMessage = "Retry delay must be between 1 and 300 seconds")]
    public int RetryDelaySeconds { get; set; } = 5;

    /// <summary>
    /// Rate limiting: maximum emails per minute
    /// Prevents overwhelming SMTP server
    /// Gmail has rate limits, this helps stay within them
    /// </summary>
    [Range(1, 1000, ErrorMessage = "Rate limit must be between 1 and 1000 emails per minute")]
    public int RateLimitPerMinute { get; set; } = 100;

    /// <summary>
    /// Enable email queue for background processing
    /// Improves application performance by sending emails asynchronously
    /// Recommended for production environments
    /// </summary>
    public bool EnableEmailQueue { get; set; } = true;

    /// <summary>
    /// Email queue processing interval in seconds
    /// How often to process queued emails
    /// Balance between performance and responsiveness
    /// </summary>
    [Range(1, 300, ErrorMessage = "Queue processing interval must be between 1 and 300 seconds")]
    public int QueueProcessingIntervalSeconds { get; set; } = 10;

    /// <summary>
    /// Maximum queue size
    /// Prevents memory issues with large email queues
    /// Should be adjusted based on application scale
    /// </summary>
    [Range(10, 10000, ErrorMessage = "Max queue size must be between 10 and 10000")]
    public int MaxQueueSize { get; set; } = 1000;

    /// <summary>
    /// Enable email logging for debugging and monitoring
    /// Logs email sending attempts, successes, and failures
    /// Useful for troubleshooting delivery issues
    /// </summary>
    public bool EnableEmailLogging { get; set; } = true;

    /// <summary>
    /// Enable email delivery tracking
    /// Tracks email delivery status and user engagement
    /// Useful for analytics and improving email templates
    /// </summary>
    public bool EnableDeliveryTracking { get; set; } = false;

    /// <summary>
    /// Default email template directory
    /// Where email templates are stored
    /// Can be file system path or embedded resources
    /// </summary>
    public string TemplateDirectory { get; set; } = "Templates/Email";

    /// <summary>
    /// Application base URL for email links
    /// Used to generate confirmation and reset links
    /// Should be your application's public URL
    /// </summary>
    [Required]
    [Url(ErrorMessage = "Application URL must be a valid URL")]
    public string ApplicationUrl { get; set; } = "https://localhost:7109";

    /// <summary>
    /// Email confirmation link expiration in hours
    /// How long email confirmation links remain valid
    /// Balance between security and user convenience
    /// </summary>
    [Range(1, 168, ErrorMessage = "Confirmation link expiration must be between 1 and 168 hours")]
    public int ConfirmationLinkExpirationHours { get; set; } = 24;

    /// <summary>
    /// Password reset link expiration in hours
    /// How long password reset links remain valid
    /// Should be shorter than confirmation links for security
    /// </summary>
    [Range(1, 24, ErrorMessage = "Reset link expiration must be between 1 and 24 hours")]
    public int ResetLinkExpirationHours { get; set; } = 2;

    /// <summary>
    /// Two-factor authentication code expiration in minutes
    /// How long 2FA codes remain valid
    /// Should be short for security but long enough for user convenience
    /// </summary>
    [Range(1, 30, ErrorMessage = "2FA code expiration must be between 1 and 30 minutes")]
    public int TwoFactorCodeExpirationMinutes { get; set; } = 5;

    /// <summary>
    /// Enable development mode
    /// In development, emails may be logged instead of sent
    /// Prevents accidental email sending during development
    /// </summary>
    public bool IsDevelopmentMode { get; set; } = false;

    /// <summary>
    /// Development mode email file path
    /// Where to save emails in development mode
    /// Useful for testing email templates without sending
    /// </summary>
    public string DevelopmentEmailFilePath { get; set; } = "wwwroot/dev-emails";

    /// <summary>
    /// Validates the email configuration for security and consistency
    /// Called during startup to ensure secure configuration
    /// Throws validation exceptions if configuration is invalid
    /// </summary>
    public void Validate()
    {
        var context = new ValidationContext(this);
        var results = new List<ValidationResult>();
        
        if (!Validator.TryValidateObject(this, context, results, true))
        {
            var errors = string.Join("; ", results.Select(r => r.ErrorMessage));
            throw new InvalidOperationException($"Email Configuration validation failed: {errors}");
        }

        // Additional business logic validation
        if (Provider == "SMTP" && string.IsNullOrEmpty(SmtpHost))
        {
            throw new InvalidOperationException("SMTP Host is required when using SMTP provider");
        }

        if (FromEmail != SmtpUsername && Provider == "SMTP" && SmtpHost.Contains("gmail"))
        {
            throw new InvalidOperationException("For Gmail SMTP, FromEmail must match SmtpUsername");
        }

        if (SmtpPort == 465 && !EnableSsl)
        {
            throw new InvalidOperationException("Port 465 requires SSL to be enabled");
        }

        if (ConfirmationLinkExpirationHours < ResetLinkExpirationHours)
        {
            throw new InvalidOperationException("Confirmation link expiration should be longer than reset link expiration");
        }
    }

    /// <summary>
    /// Gets connection timeout as TimeSpan
    /// Helper method for SMTP client configuration
    /// </summary>
    public TimeSpan ConnectionTimeout => TimeSpan.FromSeconds(ConnectionTimeoutSeconds);

    /// <summary>
    /// Gets send timeout as TimeSpan
    /// Helper method for SMTP client configuration
    /// </summary>
    public TimeSpan SendTimeout => TimeSpan.FromSeconds(SendTimeoutSeconds);

    /// <summary>
    /// Gets retry delay as TimeSpan
    /// Helper method for retry logic
    /// </summary>
    public TimeSpan RetryDelay => TimeSpan.FromSeconds(RetryDelaySeconds);

    /// <summary>
    /// Gets queue processing interval as TimeSpan
    /// Helper method for background service configuration
    /// </summary>
    public TimeSpan QueueProcessingInterval => TimeSpan.FromSeconds(QueueProcessingIntervalSeconds);

    /// <summary>
    /// Gets confirmation link expiration as TimeSpan
    /// Helper method for link generation
    /// </summary>
    public TimeSpan ConfirmationLinkExpiration => TimeSpan.FromHours(ConfirmationLinkExpirationHours);

    /// <summary>
    /// Gets reset link expiration as TimeSpan
    /// Helper method for link generation
    /// </summary>
    public TimeSpan ResetLinkExpiration => TimeSpan.FromHours(ResetLinkExpirationHours);

    /// <summary>
    /// Gets 2FA code expiration as TimeSpan
    /// Helper method for code generation
    /// </summary>
    public TimeSpan TwoFactorCodeExpiration => TimeSpan.FromMinutes(TwoFactorCodeExpirationMinutes);

    /// <summary>
    /// Checks if Gmail SMTP is being used
    /// Helper method for Gmail-specific configuration
    /// </summary>
    public bool IsGmailSmtp => SmtpHost.Contains("gmail", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gets rate limit per second for internal rate limiting
    /// Helper method for rate limiting calculations
    /// </summary>
    public double RateLimitPerSecond => RateLimitPerMinute / 60.0;
}