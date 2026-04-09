<?php namespace Golem15\User\Commands;

use Illuminate\Console\Command;
use Golem15\User\Models\FrontendPermission;

class ImportPermissions extends Command
{
    protected $signature = 'user:import-permissions {--prune : Remove permissions not found in any CSV}';

    protected $description = 'Import frontend permissions from plugins/*/*/permissions.csv and themes/*/permissions.csv files';

    public function handle()
    {
        $csvFiles = array_merge(
            glob(plugins_path('/*/*/permissions.csv')),
            glob(themes_path('*/permissions.csv'))
        );

        if (empty($csvFiles)) {
            $this->info('No permissions.csv files found.');
            return 0;
        }

        $this->info('Found ' . count($csvFiles) . ' permissions.csv file(s).');

        $added = 0;
        $updated = 0;
        $unchanged = 0;
        $allCodes = [];

        foreach ($csvFiles as $file) {
            $this->line('Processing: ' . str_replace(base_path() . '/', '', $file));

            $handle = fopen($file, 'r');
            if (!$handle) {
                $this->error('Could not open: ' . $file);
                continue;
            }

            $header = fgetcsv($handle);
            if (!$header || strtolower($header[0]) !== 'code') {
                $this->error('Invalid CSV header in: ' . $file);
                fclose($handle);
                continue;
            }

            while (($row = fgetcsv($handle)) !== false) {
                if (empty($row[0])) {
                    continue;
                }

                $code = trim($row[0]);
                $label = trim($row[1] ?? '');
                $tab = trim($row[2] ?? '');
                $comment = isset($row[3]) ? trim($row[3]) : null;

                if (!$code || !$label || !$tab) {
                    $this->warn("Skipping row with missing required fields: {$code}");
                    continue;
                }

                $allCodes[] = $code;

                $existing = FrontendPermission::where('code', $code)->first();

                if ($existing) {
                    $changes = false;
                    if ($existing->label !== $label) { $existing->label = $label; $changes = true; }
                    if ($existing->tab !== $tab) { $existing->tab = $tab; $changes = true; }
                    if ($existing->comment !== $comment) { $existing->comment = $comment; $changes = true; }

                    if ($changes) {
                        $existing->save();
                        $updated++;
                    } else {
                        $unchanged++;
                    }
                } else {
                    FrontendPermission::create([
                        'code'    => $code,
                        'label'   => $label,
                        'tab'     => $tab,
                        'comment' => $comment,
                    ]);
                    $added++;
                }
            }

            fclose($handle);
        }

        $this->info("Added: {$added}, Updated: {$updated}, Unchanged: {$unchanged}");

        if ($this->option('prune') && !empty($allCodes)) {
            $pruned = FrontendPermission::whereNotIn('code', $allCodes)->delete();
            $this->info("Pruned: {$pruned}");
        }

        return 0;
    }
}
