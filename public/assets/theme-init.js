(function () {
    var stored = null;
    try {
        stored = window.localStorage.getItem('theme');
    } catch (e) {
        /* localStorage can throw (e.g. Safari private mode) — fail open to system default */
    }
    if (stored === 'light' || stored === 'dark') {
        document.documentElement.setAttribute('data-theme', stored);
    }
})();
