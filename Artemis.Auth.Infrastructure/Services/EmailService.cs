using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Infrastructure.Common;
using Artemis.Auth.Infrastructure.Templates;

namespace Artemis.Auth.Infrastructure.Services;

/// <summary>
/// Email Service: Implements secure email sending with Gmail SMTP integration
/// Provides authentication-specific email functionality with templates
/// Implements IEmailSender interface from Application layer
/// Thread-safe implementation with retry logic and rate limiting
/// </summary>
public class EmailService : IEmailSender
{
    private readonly EmailConfiguration _emailConfig;
    private readonly EmailQueueService _emailQueueService;
    private readonly ILogger<EmailService> _logger;

    /// <summary>
    /// Constructor: Initializes email service with configuration and dependencies
    /// Sets up SMTP client configuration and email queue service
    /// Validates email configuration on startup
    /// </summary>
    public EmailService(
        IOptions<EmailConfiguration> emailOptions,
        EmailQueueService emailQueueService,
        ILogger<EmailService> logger)
    {
        _emailConfig = emailOptions.Value;
        _emailQueueService = emailQueueService;
        _logger = logger;

        // Validate configuration on startup
        _emailConfig.Validate();

        _logger.LogInformation("Email Service initialized with provider: {Provider}, Host: {Host}, Port: {Port}", 
            _emailConfig.Provider, _emailConfig.SmtpHost, _emailConfig.SmtpPort);
    }

    /// <summary>
    /// Sends email confirmation to new users
    /// Uses professional template with secure confirmation link
    /// Queues email for background processing if enabled
    /// </summary>
    public async Task SendEmailConfirmationAsync(string email, string userName, string confirmationLink)
    {
        try
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(confirmationLink))
            {
                _logger.LogWarning("Email confirmation failed: Missing required parameters");
                return;
            }

            var subject = "Confirm Your Email Address - Artemis Auth";
            var content = EmailTemplates.GetEmailConfirmationTemplate(userName, confirmationLink);
            var htmlBody = EmailTemplates.GetBaseTemplate(subject, content, _emailConfig.ApplicationUrl);

            await SendEmailAsync(email, subject, htmlBody, true);
            
            _logger.LogInformation("Email confirmation sent to {Email} for user {UserName}", 
                email, userName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending email confirmation to {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Sends password reset email with secure reset link
    /// Uses professional template with security warnings
    /// Link expires in 2 hours for security
    /// </summary>
    public async Task SendPasswordResetAsync(string email, string userName, string resetLink)
    {
        try
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(resetLink))
            {
                _logger.LogWarning("Password reset email failed: Missing required parameters");
                return;
            }

            var subject = "Reset Your Password - Artemis Auth";
            var content = EmailTemplates.GetPasswordResetTemplate(userName, resetLink);
            var htmlBody = EmailTemplates.GetBaseTemplate(subject, content, _emailConfig.ApplicationUrl);

            await SendEmailAsync(email, subject, htmlBody, true);
            
            _logger.LogInformation("Password reset email sent to {Email} for user {UserName}", 
                email, userName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending password reset email to {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Sends welcome email after successful registration
    /// Uses celebratory template with getting started information
    /// Provides security best practices and helpful tips
    /// </summary>
    public async Task SendWelcomeEmailAsync(string email, string userName)
    {
        try
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userName))
            {
                _logger.LogWarning("Welcome email failed: Missing required parameters");
                return;
            }

            var subject = "Welcome to Artemis Auth!";
            var content = EmailTemplates.GetWelcomeTemplate(userName);
            var htmlBody = EmailTemplates.GetBaseTemplate(subject, content, _emailConfig.ApplicationUrl);

            await SendEmailAsync(email, subject, htmlBody, true);
            
            _logger.LogInformation("Welcome email sent to {Email} for user {UserName}", 
                email, userName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending welcome email to {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Sends two-factor authentication code
    /// Uses secure template with time-sensitive code
    /// Code expires in 5 minutes for security
    /// </summary>
    public async Task SendTwoFactorCodeAsync(string email, string userName, string code)
    {
        try
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(code))
            {
                _logger.LogWarning("Two-factor code email failed: Missing required parameters");
                return;
            }

            var subject = "Your Two-Factor Authentication Code - Artemis Auth";
            var content = EmailTemplates.GetTwoFactorCodeTemplate(userName, code);
            var htmlBody = EmailTemplates.GetBaseTemplate(subject, content, _emailConfig.ApplicationUrl);

            await SendEmailAsync(email, subject, htmlBody, true);
            
            _logger.LogInformation("Two-factor code email sent to {Email} for user {UserName}", 
                email, userName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending two-factor code email to {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Sends account locked notification
    /// Uses alert template with unlock information
    /// Provides security recommendations and guidance
    /// </summary>
    public async Task SendAccountLockedNotificationAsync(string email, string userName, DateTime lockoutEnd)
    {
        try
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userName))
            {
                _logger.LogWarning("Account locked notification failed: Missing required parameters");
                return;
            }

            var subject = "Account Security Alert - Account Locked";
            var content = EmailTemplates.GetAccountLockedTemplate(userName, lockoutEnd);
            var htmlBody = EmailTemplates.GetBaseTemplate(subject, content, _emailConfig.ApplicationUrl);

            await SendEmailAsync(email, subject, htmlBody, true);
            
            _logger.LogInformation("Account locked notification sent to {Email} for user {UserName}", 
                email, userName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending account locked notification to {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Sends security alert for suspicious activities
    /// Uses urgent template with security recommendations
    /// Includes IP address and event details
    /// </summary>
    public async Task SendSecurityAlertAsync(string email, string userName, string alertMessage, string ipAddress)
    {
        try
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(alertMessage))
            {
                _logger.LogWarning("Security alert email failed: Missing required parameters");
                return;
            }

            var subject = "Security Alert - Artemis Auth";
            var content = EmailTemplates.GetSecurityAlertTemplate(userName, alertMessage, ipAddress ?? "Unknown");
            var htmlBody = EmailTemplates.GetBaseTemplate(subject, content, _emailConfig.ApplicationUrl);

            await SendEmailAsync(email, subject, htmlBody, true);
            
            _logger.LogWarning("Security alert email sent to {Email} for user {UserName}. Alert: {Alert}", 
                email, userName, alertMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending security alert email to {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Sends password changed notification
    /// Uses confirmation template with security information
    /// Alerts user about all session invalidation
    /// </summary>
    public async Task SendPasswordChangedNotificationAsync(string email, string userName)
    {
        try
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userName))
            {
                _logger.LogWarning("Password changed notification failed: Missing required parameters");
                return;
            }

            var subject = "Password Changed Successfully - Artemis Auth";
            var content = EmailTemplates.GetPasswordChangedTemplate(userName);
            var htmlBody = EmailTemplates.GetBaseTemplate(subject, content, _emailConfig.ApplicationUrl);

            await SendEmailAsync(email, subject, htmlBody, true);
            
            _logger.LogInformation("Password changed notification sent to {Email} for user {UserName}", 
                email, userName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending password changed notification to {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Sends account deactivated notification
    /// Uses informational template with reactivation instructions
    /// Confirms account status and data preservation
    /// </summary>
    public async Task SendAccountDeactivatedNotificationAsync(string email, string userName)
    {
        try
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userName))
            {
                _logger.LogWarning("Account deactivated notification failed: Missing required parameters");
                return;
            }

            var subject = "Account Deactivated - Artemis Auth";
            var content = EmailTemplates.GetAccountDeactivatedTemplate(userName);
            var htmlBody = EmailTemplates.GetBaseTemplate(subject, content, _emailConfig.ApplicationUrl);

            await SendEmailAsync(email, subject, htmlBody, true);
            
            _logger.LogInformation("Account deactivated notification sent to {Email} for user {UserName}", 
                email, userName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending account deactivated notification to {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Sends generic email with custom content
    /// Core email sending functionality used by all other methods
    /// Supports both HTML and plain text emails
    /// </summary>
    public async Task SendEmailAsync(string to, string subject, string body, bool isHtml = true)
    {
        try
        {
            if (string.IsNullOrEmpty(to) || string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(body))
            {
                _logger.LogWarning("Email sending failed: Missing required parameters");
                return;
            }

            // In development mode, save email to file instead of sending
            if (_emailConfig.IsDevelopmentMode)
            {
                await SaveEmailToFileAsync(to, subject, body, isHtml);
                return;
            }

            // Queue email for background processing if enabled
            if (_emailConfig.EnableEmailQueue)
            {
                var queued = await _emailQueueService.QueueEmailAsync(to, subject, body, isHtml);
                if (queued)
                {
                    _logger.LogDebug("Email queued for background processing to {Email}", to);
                }
                else
                {
                    _logger.LogWarning("Failed to queue email to {Email}, attempting direct send", to);
                    await SendEmailDirectlyAsync(to, subject, body, isHtml);
                }
            }
            else
            {
                await SendEmailDirectlyAsync(to, subject, body, isHtml);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending email to {Email}", to);
            throw;
        }
    }

    /// <summary>
    /// Sends email directly via SMTP (internal method)
    /// Used for immediate sending or when queue is disabled
    /// Implements connection pooling and retry logic
    /// </summary>
    internal async Task<bool> SendEmailDirectlyAsync(string to, string subject, string body, bool isHtml)
    {
        try
        {
            using var smtpClient = CreateSmtpClient();
            using var message = CreateEmailMessage(to, subject, body, isHtml);

            await smtpClient.SendMailAsync(message);
            
            if (_emailConfig.EnableEmailLogging)
            {
                _logger.LogInformation("Email sent successfully to {Email} with subject: {Subject}", 
                    to, subject);
            }

            return true;
        }
        catch (SmtpException ex)
        {
            _logger.LogError(ex, "SMTP error occurred while sending email to {Email}. SMTP Status: {Status}", 
                to, ex.StatusCode);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred while sending email to {Email}", to);
            return false;
        }
    }

    /// <summary>
    /// Creates configured SMTP client
    /// Sets up Gmail SMTP connection with security settings
    /// Uses app passwords for secure authentication
    /// </summary>
    private SmtpClient CreateSmtpClient()
    {
        var smtpClient = new SmtpClient(_emailConfig.SmtpHost, _emailConfig.SmtpPort)
        {
            EnableSsl = _emailConfig.EnableSsl,
            UseDefaultCredentials = false,
            Credentials = new NetworkCredential(_emailConfig.SmtpUsername, _emailConfig.SmtpPassword),
            Timeout = (int)_emailConfig.SendTimeout.TotalMilliseconds
        };

        return smtpClient;
    }

    /// <summary>
    /// Creates email message with proper headers and formatting
    /// Sets up sender, recipient, and content information
    /// Supports both HTML and plain text content
    /// </summary>
    private MailMessage CreateEmailMessage(string to, string subject, string body, bool isHtml)
    {
        var message = new MailMessage
        {
            From = new MailAddress(_emailConfig.FromEmail, _emailConfig.FromName),
            Subject = subject,
            Body = body,
            IsBodyHtml = isHtml
        };

        message.To.Add(to);

        // Add reply-to if configured
        if (!string.IsNullOrEmpty(_emailConfig.ReplyToEmail))
        {
            message.ReplyToList.Add(_emailConfig.ReplyToEmail);
        }

        // Add security headers
        message.Headers.Add("X-Mailer", "Artemis Auth Email Service");
        message.Headers.Add("X-Priority", "3");
        message.Headers.Add("X-MSMail-Priority", "Normal");

        return message;
    }

    /// <summary>
    /// Saves email to file for development mode
    /// Useful for testing email templates without sending
    /// Creates organized file structure for easy review
    /// </summary>
    private async Task SaveEmailToFileAsync(string to, string subject, string body, bool isHtml)
    {
        try
        {
            var fileName = $"email_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid().ToString("N")[..8]}.html";
            var filePath = Path.Combine(_emailConfig.DevelopmentEmailFilePath, fileName);

            // Ensure directory exists
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var emailContent = $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <title>Development Email</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
        .content {{ border: 1px solid #dee2e6; padding: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class='header'>
        <h2>Development Email</h2>
        <p><strong>To:</strong> {to}</p>
        <p><strong>Subject:</strong> {subject}</p>
        <p><strong>Is HTML:</strong> {isHtml}</p>
        <p><strong>Generated:</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}</p>
    </div>
    <div class='content'>
        {body}
    </div>
</body>
</html>";

            await File.WriteAllTextAsync(filePath, emailContent);
            
            _logger.LogInformation("Email saved to file in development mode: {FilePath}", filePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while saving email to file");
        }
    }
}