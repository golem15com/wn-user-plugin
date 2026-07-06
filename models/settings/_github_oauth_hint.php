<div>
    <p>
        Create an OAuth App at
        <a href="https://github.com/settings/developers" target="_blank" rel="noopener">GitHub Developer Settings</a>
        (OAuth Apps &rarr; New OAuth App).
    </p>
    <p>Add this exact URL as the <strong>Authorization callback URL</strong>:</p>
    <pre style="margin-bottom:0"><code><?= e(config('services.github.redirect')) ?></code></pre>
</div>
