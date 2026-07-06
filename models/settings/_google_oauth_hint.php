<div>
    <p>
        Create an OAuth 2.0 Client ID at the
        <a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener">Google Cloud Console</a>
        (APIs &amp; Services &rarr; Credentials &rarr; Create Credentials &rarr; OAuth client ID &rarr; Web application).
    </p>
    <p>Add this exact URL as an <strong>Authorized redirect URI</strong>:</p>
    <pre style="margin-bottom:0"><code><?= e(config('services.google.redirect')) ?></code></pre>
</div>
