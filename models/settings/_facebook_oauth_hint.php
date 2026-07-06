<div>
    <p>
        Create a Facebook Login use case at
        <a href="https://developers.facebook.com/apps" target="_blank" rel="noopener">Facebook for Developers</a>
        (My Apps &rarr; Create App &rarr; Consumer/Business &rarr; add the "Facebook Login" product).
    </p>
    <p>Add this exact URL as a <strong>Valid OAuth Redirect URI</strong>:</p>
    <pre style="margin-bottom:0"><code><?= e(config('services.facebook.redirect')) ?></code></pre>
</div>
