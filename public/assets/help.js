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

    function setupPageHelp() {
        var panel = document.getElementById('page-help-panel');

        if (!panel) {
            return;
        }

        var toggle = document.querySelector('.help-panel-toggle');
        var close = panel.querySelector('.help-panel-close');
        var content = panel.querySelector('.help-panel-content');

        function setOpen(open) {
            panel.hidden = !open;
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        }

        toggle.addEventListener('click', function () {
            setOpen(panel.hidden);
        });
        close.addEventListener('click', function () {
            setOpen(false);
            toggle.focus();
        });

        fetch('/help/context?path=' + encodeURIComponent(window.location.pathname), { credentials: 'same-origin' })
            .then(function (resp) {
                if (!resp.ok) {
                    throw new Error('Page help could not be loaded.');
                }

                return resp.json();
            })
            .then(function (data) {
                content.replaceChildren();

                if (!Array.isArray(data.articles) || data.articles.length === 0) {
                    var empty = document.createElement('p');
                    empty.className = 'card-sub';
                    empty.textContent = 'No contextual articles are available for this page.';
                    content.appendChild(empty);

                    return;
                }

                data.articles.forEach(function (article) {
                    var item = document.createElement('article');
                    item.className = 'help-panel-article';

                    var heading = document.createElement('h3');
                    var link = document.createElement('a');
                    link.href = article.url;
                    link.textContent = article.title;
                    heading.appendChild(link);

                    var summary = document.createElement('p');
                    summary.textContent = article.summary;
                    item.appendChild(heading);
                    item.appendChild(summary);
                    content.appendChild(item);
                });
            })
            .catch(function () {
                content.replaceChildren();
                var error = document.createElement('p');
                error.className = 'error';
                error.textContent = 'Page help could not be loaded. Visit the Help page to browse all articles.';
                content.appendChild(error);
            });
    }

    function setupOnboardingGuide() {
        var dialog = document.querySelector('.onboarding-dialog');

        if (!dialog) {
            return;
        }

        var domain = dialog.dataset.onboardingDomain;
        var storageKey = 'dmarc-onboarding-dismissed:' + encodeURIComponent(domain);
        var openButton = document.querySelector('[data-onboarding-open]');
        var dismissButtons = dialog.querySelectorAll('[data-onboarding-dismiss]');

        function isDismissed() {
            try {
                return window.localStorage.getItem(storageKey) === '1';
            } catch (error) {
                return false;
            }
        }

        function show() {
            if (!dialog.open) {
                dialog.showModal();
            }
        }

        openButton.addEventListener('click', show);
        dismissButtons.forEach(function (button) {
            button.addEventListener('click', function () {
                dialog.close();
            });
        });
        dialog.addEventListener('close', function () {
            try {
                window.localStorage.setItem(storageKey, '1');
            } catch (error) {
                // The guide still works when browser storage is unavailable.
            }
        });

        if (dialog.dataset.onboardingAutoOpen === '1') {
            if (!isDismissed()) {
                show();
            }

            var url = new URL(window.location.href);
            url.searchParams.delete('onboarding');
            window.history.replaceState(null, '', url.pathname + url.search + url.hash);
        }
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

                var panel = document.getElementById('page-help-panel');

                if (panel && !panel.hidden) {
                    panel.hidden = true;
                    var toggle = document.querySelector('.help-panel-toggle');
                    toggle.setAttribute('aria-expanded', 'false');
                    toggle.focus();
                }
            }
        });

        // position:fixed tracks the viewport, not the trigger — rather than
        // re-computing on every scroll/resize tick, just close on either,
        // same as most native browser tooltips do.
        window.addEventListener('scroll', closePopover, true);
        window.addEventListener('resize', closePopover);
        setupPageHelp();
        setupOnboardingGuide();
    });
})();
