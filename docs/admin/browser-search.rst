.. _browser search worker:

Server-side browser search worker
=================================

The optional browser search worker runs Chromium on the same server as the
SearXNG instance.  It is disabled by default and is exposed only on the
configured loopback address.  The ``google browser`` engine sends structured
requests to the worker and receives normalized search results.

Installation
------------

Install the optional dependency in the SearXNG virtual environment.  Install
the Playwright browser into the path used by the systemd unit::

  pip install -e '.[browser-search]'
  sudo -u searxng env PLAYWRIGHT_BROWSERS_PATH=/var/lib/searxng/playwright playwright install chromium

The worker is started with the ``searxng-browser-search`` entry point.  A
systemd unit template is included at
``utils/templates/etc/systemd/system/searxng-browser-search.service``.

Configuration
-------------

Enable the worker and the engine in the instance settings::

  browser_search:
    enabled: true
    bind_address: "127.0.0.1"
    port: 8890
    endpoint: "http://127.0.0.1:8890"
    profile_dir: "/var/lib/searxng/browser-profiles"
    browser_channel: "chrome"
    challenge_retry_delay: 2
    max_attempts: 3
    proxy_pool:
      enabled: false
      entries: []

  engines:
    - name: google browser
      engine: google_browser
      shortcut: gob
      disabled: false
      timeout: 135.0

Proxy entries accept ``socks5://``, ``http://`` and ``https://`` URLs.  Each
proxy gets a separate persistent browser profile.  A search starts direct,
clears the current route's cookies after a recognized Google challenge or rate
limit.  A first challenge is retried on the same route after
``challenge_retry_delay`` seconds (bounded to 10 seconds); only a repeated
challenge causes cookie cleanup and route rotation.  Rate limits and HTTP
access denials rotate without clearing cookies.  Transient route connection
errors also rotate without clearing cookies.  The worker advances through the
proxy pool until it succeeds, reaches ``max_attempts``, or completes one proxy
round.

Authenticated SOCKS5 URLs are supported through an in-process loopback bridge,
because Chromium does not accept SOCKS5 credentials directly.  The upstream
username and password are not passed to Chromium or written to worker logs.

The default ``browser_channel`` prefers the system Google Chrome build and
falls back to Playwright Chromium when Chrome is not installed.  The worker
detects the active browser version when ``user_agent`` is empty.  In headless
mode it removes only the ``HeadlessChrome`` label while retaining that detected
version, keeping it aligned with the browser's client hints.  Each route context
starts with the locale requested by SearXNG.  Successful route contexts and
cookies are reused.  They are cleared only after a recognized challenge or rate
limit.  Keeping each route's profile directory between worker restarts is
important: an established profile is substantially less likely to receive an
immediate Google challenge than a new profile.

The worker never logs proxy credentials or browser cookies.  Keep the worker
bound to a private address and protect the profile directory with filesystem
permissions.
