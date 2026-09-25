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
    max_concurrent_pages: 2
    google_max_concurrent_pages: 1
    challenge_retry_delay: 2
    recovery_retries_per_route: 1
    max_route_attempts: 3
    route_cooldown_seconds: 10
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

Proxy entries accept ``socks5://``, ``http://`` and ``https://`` URLs.  The
worker launches one Chromium instance for its lifetime.  Each engine and proxy
route receives its own replaceable BrowserContext inside that one instance.
Google requests are serialized by ``google_max_concurrent_pages``; later
requests wait at the browser-search stage and do not rerun upstream query
generation.

A search starts direct.  On a recognized challenge, rate limit, or route
failure, the current Page and Context are discarded without overwriting the
last successful storage state.  After ``challenge_retry_delay`` seconds, the
  same route is recreated from that last-good state and retried once according to
  ``recovery_retries_per_route``.  A failed recovery leaves a clean Context for
the next queued request, applies a route cooldown bounded to 10 seconds, and
allows the search to rotate through up to ``max_route_attempts`` routes.  A
challenge Context is never reused, and failed Context state is never saved.

Authenticated SOCKS5 URLs are supported through an in-process loopback bridge,
because Chromium does not accept SOCKS5 credentials directly.  The upstream
username and password are not passed to Chromium or written to worker logs.

The default ``browser_channel`` prefers the system Google Chrome build and
falls back to Playwright Chromium when Chrome is not installed.  The worker
detects the active browser version when ``user_agent`` is empty.  In headless
mode it removes only the ``HeadlessChrome`` label while retaining that detected
version, keeping it aligned with the browser's client hints.  Each route context
 starts with the locale requested by SearXNG.  Only successful contexts update
the route's ``storage-state.json`` atomically.  Keeping each route's state file
between worker restarts preserves the normal Google identity without carrying a
challenged Context forward.

Every browser host and child Context also receives the same page-level identity
initialization before navigation.  This keeps ``navigator.webdriver``, plugins,
languages, and the Chrome runtime consistent with the selected Chrome channel;
the initialization is not a challenge solver.

``max_concurrent_pages`` controls the total number of active search pages, and
``google_max_concurrent_pages`` controls the Google lane specifically.  Extra
requests wait in the worker's async queue and do not start another browser.

The worker never logs proxy credentials or browser cookies.  Keep the worker
bound to a private address and protect the profile directory with filesystem
permissions.
