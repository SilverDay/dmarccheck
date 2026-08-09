/*
 * Floating popovers (docs/feature-helpsystem.md §4.1/§6.2, and the
 * "Fix me" health-check buttons that reuse the same mechanism). Vanilla
 * JS, no build step, matching the project's no-framework convention.
 * position:fixed, positioned via getBoundingClientRect() and appended to
 * <body> — an in-flow popover was tried first but grid layouts (e.g.
 * .health-grid) stretch every cell in a row to match the tallest one, so
 * any in-flow content growth in a single cell inflated the whole row.
 * Fully out of document flow, this can't happen no matter which
 * container the trigger lives in.
 */
(function () {
    var MARGIN = 8;
    var FALLBACK_WIDTH = 320;

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

    function positionPopover(button, popover) {
        var rect = button.getBoundingClientRect();
        var width = popover.offsetWidth || FALLBACK_WIDTH;
        var left = Math.min(rect.left, window.innerWidth - width - MARGIN);
        left = Math.max(left, MARGIN);

        var top = rect.bottom + 6;

        popover.style.left = left + 'px';
        popover.style.top = top + 'px';
    }

    /** @param contentNode a DOM node to insert as the popover's content (caller builds it) */
    function openPopover(button, contentNode, extraClass) {
        closePopover();

        var id = 'popover-' + Math.random().toString(36).slice(2);
        var popover = document.createElement('div');
        popover.className = extraClass ? 'help-popover ' + extraClass : 'help-popover';
        popover.id = id;
        popover.setAttribute('role', 'dialog');
        popover.appendChild(contentNode);

        document.body.appendChild(popover);
        positionPopover(button, popover);

        button.setAttribute('aria-expanded', 'true');
        button.setAttribute('aria-describedby', id);

        activePopover = popover;
        activeButton = button;
    }

    function loadAndOpenHelp(button) {
        var slug = button.dataset.helpSlug;

        fetch('/help/inline?slug=' + encodeURIComponent(slug), { credentials: 'same-origin' })
            .then(function (resp) {
                return resp.ok ? resp.json() : null;
            })
            .then(function (data) {
                if (!data) {
                    return;
                }

                var fragment = document.createDocumentFragment();

                var summary = document.createElement('p');
                summary.textContent = data.summary;
                fragment.appendChild(summary);

                var link = document.createElement('a');
                link.href = data.moreUrl;
                link.textContent = 'Learn more →';
                fragment.appendChild(link);

                openPopover(button, fragment);
            });
    }

    function openFix(button) {
        var template = document.getElementById(button.dataset.fixTarget);

        if (!(template instanceof HTMLTemplateElement)) {
            return;
        }

        openPopover(button, template.content.cloneNode(true), 'fix-popover');
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('.help-trigger, .fix-trigger').forEach(function (button) {
            button.setAttribute('aria-expanded', 'false');
            button.addEventListener('click', function (event) {
                event.preventDefault();
                event.stopPropagation();

                if (activeButton === button) {
                    closePopover();

                    return;
                }

                if (button.classList.contains('fix-trigger')) {
                    openFix(button);
                } else {
                    loadAndOpenHelp(button);
                }
            });
        });

        document.addEventListener('click', function (event) {
            if (activePopover && event.target !== activeButton && !activePopover.contains(event.target)) {
                closePopover();
            }

            // Delegated (not queried once at load) so it also covers copy
            // buttons cloned from a <template> into a "Fix me" popover.
            var copyBtn = event.target.closest ? event.target.closest('.copy-btn') : null;

            if (copyBtn) {
                var value = copyBtn.dataset.copyValue || '';

                navigator.clipboard.writeText(value).then(function () {
                    copyBtn.textContent = 'Copied!';
                }, function () {
                    copyBtn.textContent = 'Copy failed';
                }).finally(function () {
                    setTimeout(function () {
                        copyBtn.textContent = 'Copy';
                    }, 2000);
                });
            }
        });

        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') {
                closePopover();
            }
        });

        // position:fixed tracks the viewport, not the trigger — rather than
        // re-computing on every scroll/resize tick, just close on either,
        // same as most native browser tooltips do.
        window.addEventListener('scroll', closePopover, true);
        window.addEventListener('resize', closePopover);
    });
})();
