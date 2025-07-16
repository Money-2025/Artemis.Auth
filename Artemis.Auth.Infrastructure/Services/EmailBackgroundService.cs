using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Services;

/// <summary>
/// Email Background Service: Processes queued emails in the background
/// Implements IHostedService for automatic startup with the application
/// Provides continuous email processing with configurable intervals
/// Monitors queue performance and handles failures gracefully
/// </summary>
public class EmailBackgroundService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly EmailConfiguration _emailConfig;
    private readonly ILogger<EmailBackgroundService> _logger;

    /// <summary>
    /// Constructor: Initializes background service with dependencies
    /// Uses service provider to resolve scoped services in background thread
    /// Configures processing interval from email configuration
    /// </summary>
    public EmailBackgroundService(
        IServiceProvider serviceProvider,
        IOptions<EmailConfiguration> emailOptions,
        ILogger<EmailBackgroundService> logger)
    {
        _serviceProvider = serviceProvider;
        _emailConfig = emailOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Background service execution method
    /// Runs continuously while the application is running
    /// Processes email queue at regular intervals
    /// Handles exceptions to prevent service termination
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Email background service started");

        // Wait for application to be fully started
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_emailConfig.EnableEmailQueue)
                {
                    await ProcessEmailQueueAsync(stoppingToken);
                }
                else
                {
                    // If queue is disabled, wait longer before checking again
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when cancellation is requested
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred in email background service");
                
                // Wait before retrying to avoid rapid error loops
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }

        _logger.LogInformation("Email background service stopped");
    }

    /// <summary>
    /// Processes the email queue using scoped services
    /// Creates new service scope for each processing cycle
    /// Ensures proper disposal of resources
    /// </summary>
    private async Task ProcessEmailQueueAsync(CancellationToken stoppingToken)
    {
        using var scope = _serviceProvider.CreateScope();
        var emailQueueService = scope.ServiceProvider.GetRequiredService<EmailQueueService>();
        var emailService = scope.ServiceProvider.GetRequiredService<EmailService>();

        try
        {
            // Process queued emails
            var processedCount = await emailQueueService.ProcessQueueAsync(
                (to, subject, body, isHtml) => SendEmailWithRetryAsync(emailService, to, subject, body, isHtml));

            // Log queue statistics periodically
            if (processedCount > 0)
            {
                var stats = await emailQueueService.GetQueueStatsAsync();
                _logger.LogInformation("Email queue processing completed. Processed: {ProcessedCount}, " +
                    "Queue size: {QueueSize}, Rate utilization: {RateUtilization:F1}%",
                    processedCount, stats.TotalQueueSize, stats.RateLimitUtilization);
            }

            // Wait for next processing cycle
            await Task.Delay(_emailConfig.QueueProcessingInterval, stoppingToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while processing email queue");
            throw;
        }
    }

    /// <summary>
    /// Sends email with retry logic for the queue processor
    /// Wraps direct email sending with additional error handling
    /// Returns success/failure status for queue management
    /// </summary>
    private async Task<bool> SendEmailWithRetryAsync(EmailService emailService, string to, string subject, string body, bool isHtml)
    {
        try
        {
            // Use reflection to call the private SendEmailDirectlyAsync method
            // This is needed because the queue processor needs direct access to sending
            var method = typeof(EmailService).GetMethod("SendEmailDirectlyAsync", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            if (method != null)
            {
                var task = (Task<bool>)method.Invoke(emailService, new object[] { to, subject, body, isHtml })!;
                return await task;
            }
            else
            {
                // Fallback to public method if reflection fails
                await emailService.SendEmailAsync(to, subject, body, isHtml);
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending email to {Email}", to);
            return false;
        }
    }

    /// <summary>
    /// Handles service stop gracefully
    /// Logs service shutdown and performs cleanup
    /// </summary>
    public override async Task StopAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Email background service is stopping");
        
        await base.StopAsync(stoppingToken);
        
        _logger.LogInformation("Email background service stopped gracefully");
    }
}