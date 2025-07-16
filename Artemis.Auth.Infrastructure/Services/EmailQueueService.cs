using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Services;

/// <summary>
/// Email Queue Item: Represents a queued email message
/// Contains all necessary information for email delivery
/// Used by EmailQueueService for background processing
/// </summary>
public class EmailQueueItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string To { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public bool IsHtml { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public int AttemptCount { get; set; } = 0;
    public DateTime NextAttemptAt { get; set; } = DateTime.UtcNow;
    public string? LastError { get; set; }
    public bool IsProcessing { get; set; } = false;
}

/// <summary>
/// Email Queue Service: Manages background email processing and retry logic
/// Implements thread-safe queue with rate limiting and exponential backoff
/// Processes emails asynchronously to improve application performance
/// </summary>
public class EmailQueueService
{
    private readonly ConcurrentQueue<EmailQueueItem> _emailQueue;
    private readonly ConcurrentDictionary<string, EmailQueueItem> _processingItems;
    private readonly EmailConfiguration _emailConfig;
    private readonly ILogger<EmailQueueService> _logger;
    private readonly SemaphoreSlim _processingLock;
    private readonly Timer _rateLimitTimer;
    private int _emailsSentThisMinute;
    private DateTime _lastRateLimitReset;

    /// <summary>
    /// Constructor: Initializes email queue with rate limiting
    /// Sets up processing locks and rate limit tracking
    /// Configures automatic rate limit reset timer
    /// </summary>
    public EmailQueueService(
        IOptions<EmailConfiguration> emailOptions,
        ILogger<EmailQueueService> logger)
    {
        _emailConfig = emailOptions.Value;
        _logger = logger;
        _emailQueue = new ConcurrentQueue<EmailQueueItem>();
        _processingItems = new ConcurrentDictionary<string, EmailQueueItem>();
        _processingLock = new SemaphoreSlim(1, 1);
        _emailsSentThisMinute = 0;
        _lastRateLimitReset = DateTime.UtcNow;

        // Setup rate limit reset timer
        _rateLimitTimer = new Timer(ResetRateLimit, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

        _logger.LogInformation("Email queue service initialized with rate limit: {RateLimit} emails/minute", 
            _emailConfig.RateLimitPerMinute);
    }

    /// <summary>
    /// Queues an email for background processing
    /// Validates queue capacity and email parameters
    /// Thread-safe operation with queue size management
    /// </summary>
    public async Task<bool> QueueEmailAsync(string to, string subject, string body, bool isHtml = true)
    {
        try
        {
            if (string.IsNullOrEmpty(to) || string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(body))
            {
                _logger.LogWarning("Email queue attempt failed: Missing required parameters");
                return false;
            }

            if (!_emailConfig.EnableEmailQueue)
            {
                _logger.LogWarning("Email queue is disabled. Email will not be queued.");
                return false;
            }

            // Check queue capacity
            if (_emailQueue.Count >= _emailConfig.MaxQueueSize)
            {
                _logger.LogWarning("Email queue is full. Current size: {CurrentSize}, Max size: {MaxSize}", 
                    _emailQueue.Count, _emailConfig.MaxQueueSize);
                return false;
            }

            var emailItem = new EmailQueueItem
            {
                To = to,
                Subject = subject,
                Body = body,
                IsHtml = isHtml
            };

            _emailQueue.Enqueue(emailItem);
            
            _logger.LogDebug("Email queued successfully. Queue size: {QueueSize}, Email ID: {EmailId}", 
                _emailQueue.Count, emailItem.Id);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while queuing email");
            return false;
        }
    }

    /// <summary>
    /// Processes queued emails with rate limiting and retry logic
    /// Called by background service at regular intervals
    /// Implements exponential backoff for failed emails
    /// </summary>
    public async Task<int> ProcessQueueAsync(Func<string, string, string, bool, Task<bool>> sendEmailFunc)
    {
        if (!_emailConfig.EnableEmailQueue)
            return 0;

        await _processingLock.WaitAsync();
        try
        {
            var processedCount = 0;
            var now = DateTime.UtcNow;

            // Process emails while respecting rate limits
            while (_emailQueue.TryDequeue(out var emailItem) && 
                   _emailsSentThisMinute < _emailConfig.RateLimitPerMinute)
            {
                // Check if it's time to attempt this email
                if (emailItem.NextAttemptAt > now)
                {
                    // Re-queue for later processing
                    _emailQueue.Enqueue(emailItem);
                    continue;
                }

                // Skip if already processing
                if (emailItem.IsProcessing)
                {
                    _emailQueue.Enqueue(emailItem);
                    continue;
                }

                // Mark as processing
                emailItem.IsProcessing = true;
                _processingItems.TryAdd(emailItem.Id, emailItem);

                try
                {
                    // Attempt to send email
                    emailItem.AttemptCount++;
                    _logger.LogDebug("Processing email {EmailId}, attempt {AttemptCount}", 
                        emailItem.Id, emailItem.AttemptCount);

                    var success = await sendEmailFunc(emailItem.To, emailItem.Subject, emailItem.Body, emailItem.IsHtml);

                    if (success)
                    {
                        _logger.LogDebug("Email sent successfully: {EmailId}", emailItem.Id);
                        _emailsSentThisMinute++;
                        processedCount++;
                    }
                    else
                    {
                        // Handle send failure
                        await HandleEmailFailureAsync(emailItem, "Email sending failed");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred while processing email {EmailId}", emailItem.Id);
                    await HandleEmailFailureAsync(emailItem, ex.Message);
                }
                finally
                {
                    // Remove from processing
                    emailItem.IsProcessing = false;
                    _processingItems.TryRemove(emailItem.Id, out _);
                }
            }

            // Re-queue any remaining processing items
            foreach (var item in _processingItems.Values)
            {
                if (!item.IsProcessing)
                {
                    _emailQueue.Enqueue(item);
                    _processingItems.TryRemove(item.Id, out _);
                }
            }

            if (processedCount > 0)
            {
                _logger.LogInformation("Processed {ProcessedCount} emails. Queue size: {QueueSize}, Rate limit: {RateUsed}/{RateLimit}", 
                    processedCount, _emailQueue.Count, _emailsSentThisMinute, _emailConfig.RateLimitPerMinute);
            }

            return processedCount;
        }
        finally
        {
            _processingLock.Release();
        }
    }

    /// <summary>
    /// Handles email sending failures with exponential backoff
    /// Implements retry logic with configurable maximum attempts
    /// Removes permanently failed emails from queue
    /// </summary>
    private async Task HandleEmailFailureAsync(EmailQueueItem emailItem, string error)
    {
        emailItem.LastError = error;

        if (emailItem.AttemptCount >= _emailConfig.MaxRetryAttempts)
        {
            _logger.LogError("Email permanently failed after {MaxAttempts} attempts: {EmailId}. Error: {Error}", 
                _emailConfig.MaxRetryAttempts, emailItem.Id, error);
            
            // Could implement dead letter queue here
            return;
        }

        // Calculate exponential backoff delay
        var delayMinutes = Math.Pow(2, emailItem.AttemptCount - 1) * _emailConfig.RetryDelaySeconds / 60.0;
        emailItem.NextAttemptAt = DateTime.UtcNow.AddMinutes(delayMinutes);

        // Re-queue for retry
        _emailQueue.Enqueue(emailItem);
        
        _logger.LogWarning("Email {EmailId} failed (attempt {AttemptCount}), scheduled for retry at {RetryTime}. Error: {Error}", 
            emailItem.Id, emailItem.AttemptCount, emailItem.NextAttemptAt, error);
    }

    /// <summary>
    /// Gets current queue statistics
    /// Used for monitoring and debugging
    /// Provides insight into queue performance
    /// </summary>
    public async Task<EmailQueueStats> GetQueueStatsAsync()
    {
        await _processingLock.WaitAsync();
        try
        {
            var now = DateTime.UtcNow;
            var queueItems = _emailQueue.ToArray();
            
            return new EmailQueueStats
            {
                TotalQueueSize = _emailQueue.Count,
                ProcessingCount = _processingItems.Count,
                EmailsSentThisMinute = _emailsSentThisMinute,
                RateLimitPerMinute = _emailConfig.RateLimitPerMinute,
                PendingImmediateCount = queueItems.Count(e => e.NextAttemptAt <= now),
                PendingRetryCount = queueItems.Count(e => e.NextAttemptAt > now),
                LastRateLimitReset = _lastRateLimitReset
            };
        }
        finally
        {
            _processingLock.Release();
        }
    }

    /// <summary>
    /// Clears all queued emails
    /// Used for maintenance or emergency situations
    /// Logs the action for audit purposes
    /// </summary>
    public async Task ClearQueueAsync()
    {
        await _processingLock.WaitAsync();
        try
        {
            var clearedCount = _emailQueue.Count;
            while (_emailQueue.TryDequeue(out _)) { }
            
            _logger.LogWarning("Email queue cleared. {ClearedCount} emails removed", clearedCount);
        }
        finally
        {
            _processingLock.Release();
        }
    }

    /// <summary>
    /// Resets the rate limit counter
    /// Called automatically every minute by timer
    /// Ensures consistent rate limiting behavior
    /// </summary>
    private void ResetRateLimit(object? state)
    {
        try
        {
            var previousCount = _emailsSentThisMinute;
            _emailsSentThisMinute = 0;
            _lastRateLimitReset = DateTime.UtcNow;
            
            if (previousCount > 0)
            {
                _logger.LogDebug("Rate limit reset. Previous minute: {PreviousCount} emails sent", previousCount);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while resetting rate limit");
        }
    }

    /// <summary>
    /// Disposes resources and stops timers
    /// Called during application shutdown
    /// Ensures proper cleanup of resources
    /// </summary>
    public void Dispose()
    {
        try
        {
            _rateLimitTimer?.Dispose();
            _processingLock?.Dispose();
            
            var queueSize = _emailQueue.Count;
            if (queueSize > 0)
            {
                _logger.LogWarning("Email queue service disposed with {QueueSize} emails remaining", queueSize);
            }
            
            _logger.LogInformation("Email queue service disposed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while disposing email queue service");
        }
    }
}

/// <summary>
/// Email Queue Statistics: Provides insights into queue performance
/// Used for monitoring and debugging email processing
/// </summary>
public class EmailQueueStats
{
    public int TotalQueueSize { get; set; }
    public int ProcessingCount { get; set; }
    public int EmailsSentThisMinute { get; set; }
    public int RateLimitPerMinute { get; set; }
    public int PendingImmediateCount { get; set; }
    public int PendingRetryCount { get; set; }
    public DateTime LastRateLimitReset { get; set; }
    public double RateLimitUtilization => RateLimitPerMinute > 0 ? (double)EmailsSentThisMinute / RateLimitPerMinute * 100 : 0;
}