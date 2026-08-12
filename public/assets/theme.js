(function () {
    document.addEventListener('DOMContentLoaded', function () {
        var buttons = document.querySelectorAll('.theme-toggle');
        if (!buttons.length) {
            return;
        }

        function currentTheme() {
            var explicit = document.documentElement.getAttribute('data-theme');
            if (explicit === 'light' || explicit === 'dark') {
                return explicit;
            }
            var systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            return systemDark ? 'dark' : 'light';
        }

        function updateButtons(theme) {
            var i;
            for (i = 0; i < buttons.length; i++) {
                buttons[i].setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
                buttons[i].setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
            }
        }

        function applyTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            try {
                window.localStorage.setItem('theme', theme);
            } catch (e) {
                /* ignore — theme still applies for this pageview via the attribute */
            }
            updateButtons(theme);
        }

        updateButtons(currentTheme());

        var i;
        for (i = 0; i < buttons.length; i++) {
            buttons[i].addEventListener('click', function () {
                applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
            });
        }
    });
})();
