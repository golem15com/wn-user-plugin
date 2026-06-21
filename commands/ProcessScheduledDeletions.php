<?php namespace Golem15\User\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Console\Attribute\AsCommand;
use Golem15\User\Models\User;
use Log;

/**
 * Process Scheduled Account Deletions
 *
 * This command processes users who have requested account deletion
 * and whose 30-day grace period has expired. It performs a hard delete
 * (permanent removal) of their account and all associated data.
 *
 * Should be scheduled to run daily via cron:
 * 0 2 * * * php artisan user:process-scheduled-deletions
 */
#[AsCommand(name: 'user:process-scheduled-deletions')]
class ProcessScheduledDeletions extends Command
{
    /**
     * @var string The console command signature
     */
    protected $signature = 'user:process-scheduled-deletions';

    /**
     * @var string The console command description
     */
    protected $description = 'Process users scheduled for deletion (30-day grace period expired)';

    /**
     * Execute the console command
     */
    public function handle()
    {
        $this->info('Processing scheduled account deletions...');

        // Find users whose deletion grace period has expired
        $users = User::whereNotNull('deletion_scheduled_for')
            ->where('deletion_scheduled_for', '<=', now())
            ->get();

        if ($users->isEmpty()) {
            $this->info('No accounts scheduled for deletion.');
            return 0;
        }

        $this->info("Found {$users->count()} accounts to delete.");

        $successCount = 0;
        $failureCount = 0;

        foreach ($users as $user) {
            try {
                $userId = $user->id;
                $userEmail = $user->email;

                $this->info("Deleting user: {$userEmail} (ID: {$userId})");

                // Perform hard delete (permanent removal)
                $user->hardDelete();

                $successCount++;
                $this->info("✓ User deleted successfully");

                // Log successful deletion
                Log::warning("Scheduled deletion completed", [
                    'user_id' => $userId,
                    'email' => $userEmail,
                    'scheduled_for' => $user->deletion_scheduled_for,
                ]);

            } catch (\Exception $e) {
                $failureCount++;
                $this->error("✗ Failed to delete user {$user->id}: {$e->getMessage()}");

                Log::error("Scheduled deletion failed", [
                    'user_id' => $user->id,
                    'email' => $user->email,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ]);
            }
        }

        // Summary
        $this->info("\nScheduled deletions processing complete.");
        $this->info("Successfully deleted: {$successCount}");

        if ($failureCount > 0) {
            $this->error("Failed: {$failureCount}");
        }

        return 0;
    }
}
