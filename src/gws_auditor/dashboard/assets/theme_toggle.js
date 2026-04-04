/**
 * Dark mode toggle – pure JS, loaded automatically by Dash from assets/.
 * Persists preference in localStorage and applies data-theme attribute.
 * Also restyles Plotly charts when theme changes or new charts appear.
 */
(function () {
    var STORAGE_KEY = "gws-auditor-theme";

    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        var btn = document.getElementById("theme-toggle");
        if (btn) {
            btn.innerHTML =
                theme === "dark"
                    ? '<span style="margin-right:0.4rem">\u2600\uFE0F</span>Light Mode'
                    : '<span style="margin-right:0.4rem">\uD83C\uDF19</span>Dark Mode';
        }
        // Update any existing Plotly charts
        updatePlotlyTheme(theme);
    }

    function updatePlotlyTheme(theme) {
        var fontColor = theme === "dark" ? "#f3f4f6" : "#2d3748";
        var gridColor = theme === "dark" ? "#374151" : "#e2e8f0";
        var plots = document.querySelectorAll(".js-plotly-plot");
        plots.forEach(function (plot) {
            if (plot && typeof Plotly !== "undefined") {
                try {
                    Plotly.relayout(plot, {
                        "font.color": fontColor,
                        "title.font.color": fontColor,
                        "xaxis.tickfont.color": fontColor,
                        "yaxis.tickfont.color": fontColor,
                        "xaxis.title.font.color": fontColor,
                        "yaxis.title.font.color": fontColor,
                        "xaxis.gridcolor": gridColor,
                        "yaxis.gridcolor": gridColor,
                        "legend.font.color": fontColor,
                        "piecolorway": undefined,
                    });
                } catch (e) { /* chart may not be fully initialized */ }
            }
        });
    }

    function getStoredTheme() {
        try {
            return localStorage.getItem(STORAGE_KEY) || "light";
        } catch (e) {
            return "light";
        }
    }

    function storeTheme(theme) {
        try {
            localStorage.setItem(STORAGE_KEY, theme);
        } catch (e) {
            /* ignore */
        }
    }

    // Apply stored theme on load
    applyTheme(getStoredTheme());

    // Attach click handler once DOM is ready
    function attachToggle() {
        var btn = document.getElementById("theme-toggle");
        if (!btn) {
            setTimeout(attachToggle, 200);
            return;
        }
        if (btn._themeHandlerAttached) return;
        btn._themeHandlerAttached = true;

        btn.addEventListener("click", function () {
            var current = document.documentElement.getAttribute("data-theme") || "light";
            var next = current === "dark" ? "light" : "dark";
            storeTheme(next);
            // Clear tracked plots so all charts get re-styled
            _plotlyRestyled = new WeakSet();
            applyTheme(next);
        });

        applyTheme(getStoredTheme());
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", attachToggle);
    } else {
        attachToggle();
    }

    // Watch for DOM changes: new charts appearing or Dash re-renders
    var _plotlyRestyled = new WeakSet();
    var observer = new MutationObserver(function () {
        // Re-attach toggle button if Dash re-rendered it
        var btn = document.getElementById("theme-toggle");
        if (btn && !btn._themeHandlerAttached) {
            attachToggle();
        }

        // Restyle any new Plotly charts that appeared
        var theme = getStoredTheme();
        if (theme === "dark") {
            var plots = document.querySelectorAll(".js-plotly-plot");
            plots.forEach(function (plot) {
                if (!_plotlyRestyled.has(plot)) {
                    _plotlyRestyled.add(plot);
                    // Small delay to let Plotly finish rendering
                    setTimeout(function () {
                        updatePlotlyTheme(theme);
                    }, 100);
                }
            });
        }
    });
    observer.observe(document.body || document.documentElement, {
        childList: true,
        subtree: true,
    });
})();
