/*
 * Help-tooltip popover (docs/feature-helpsystem.md §4.1/§6.2). Vanilla JS,
 * no build step, matching the project's no-framework convention. Fetches
 * /help/inline?slug= (auth-gated, dashboard-only) and renders a small
 * popover inserted right after the trigger button in normal document flow
 * — no position:fixed/JS coordinate math, kept deliberately simple.
 */
(function () {
    var activePopover = null;
    var activeButton = null;

    function closePopover() {
        if (activePopover) {
            activePopover.remove();
            activePopover = null;
        }
        if (activeButton) {
            activeButton.setAttribute('aria-expanded', 'false');
            activeButton.removeAttribute('aria-describedby');
            activeButton = null;
        }
    }

    function openPopover(button, data) {
        closePopover();

        var id = 'help-popover-' + Math.random().toString(36).slice(2);
        var popover = document.createElement('div');
        popover.className = 'help-popover';
        popover.id = id;
        popover.setAttribute('role', 'tooltip');

        var summary = document.createElement('p');
        summary.textContent = data.summary;
        popover.appendChild(summary);

        var link = document.createElement('a');
        link.href = data.moreUrl;
        link.textContent = 'Learn more →';
        popover.appendChild(link);

        button.insertAdjacentElement('afterend', popover);
        button.setAttribute('aria-expanded', 'true');
        button.setAttribute('aria-describedby', id);

        activePopover = popover;
        activeButton = button;
    }

    function loadAndOpen(button) {
        var slug = button.dataset.helpSlug;

        fetch('/help/inline?slug=' + encodeURIComponent(slug), { credentials: 'same-origin' })
            .then(function (resp) {
                return resp.ok ? resp.json() : null;
            })
            .then(function (data) {
                if (data) {
                    openPopover(button, data);
                }
            });
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('.help-trigger').forEach(function (button) {
            button.setAttribute('aria-expanded', 'false');
            button.addEventListener('click', function (event) {
                event.preventDefault();
                event.stopPropagation();

                if (activeButton === button) {
                    closePopover();

                    return;
                }

                loadAndOpen(button);
            });
        });

        document.addEventListener('click', function (event) {
            if (activePopover && event.target !== activeButton && !activePopover.contains(event.target)) {
                closePopover();
            }
        });

        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') {
                closePopover();
            }
        });
    });
})();
