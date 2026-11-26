.pragma library

function formatReset(ms) {
    if (!ms || ms <= 0) return ""
    var d = new Date(ms)
    if (isNaN(d.getTime())) return ""
    var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    var h = d.getHours()
    var m = d.getMinutes()
    var ap = h < 12 ? "am" : "pm"
    var h12 = h % 12
    if (h12 === 0) h12 = 12
    var time = m === 0 ? ("" + h12 + ap)
                       : (h12 + ":" + (m < 10 ? "0" : "") + m + ap)
    return months[d.getMonth()] + " " + d.getDate() + ", " + time
}

function durationLabel(seconds) {
    if (!seconds || seconds <= 0) return "limit"
    if (seconds < 86400) return Math.max(1, Math.round(seconds / 3600)) + "h"
    if (seconds < 1209600) return "week"
    return Math.round(seconds / 86400) + "d"
}

function windowEntry(w, prefix) {
    if (!w || typeof w !== "object") return null
    var pct = NaN
    if (typeof w.used_percent === "number") pct = w.used_percent
    else if (typeof w.used_percent === "string") pct = parseFloat(w.used_percent)
    if (!isFinite(pct)) return null
    var seconds = (typeof w.limit_window_seconds === "number") ? w.limit_window_seconds : 0
    var resetsAt = 0
    if (typeof w.reset_at === "number") resetsAt = w.reset_at * 1000
    else if (typeof w.reset_after_seconds === "number") resetsAt = Date.now() + w.reset_after_seconds * 1000
    var short = durationLabel(seconds)
    var label = (seconds > 0 && seconds <= 86400) ? "session"
              : (seconds > 86400 && seconds <= 1209600) ? "week (all models)"
              : short
    if (prefix && prefix.length > 0) label = prefix + " " + short
    return {
        label: label,
        percent: Math.max(0, Math.min(100, Math.round(pct))),
        resets: formatReset(resetsAt),
        resetsAt: resetsAt,
        severity: "",
        windowSeconds: seconds
    }
}

function parseUsage(jsonText) {
    var result = {
        ok: false,
        error: null,
        session: null,
        week: null,
        extraLimits: [],
        raw: jsonText || ""
    }

    if (!jsonText || jsonText.trim().length === 0) {
        result.error = "Empty API response"
        return result
    }

    var data
    try {
        data = JSON.parse(jsonText)
    } catch (e) {
        result.error = "Invalid API response"
        return result
    }

    if (!data || typeof data !== "object") {
        result.error = "Empty API response"
        return result
    }

    if (data.error) {
        result.error = (typeof data.error === "string")
                     ? data.error
                     : (data.error.message || "API error")
        return result
    }

    var rate = data.rate_limit || {}
    var windows = []
    var primary = windowEntry(rate.primary_window, "")
    var secondary = windowEntry(rate.secondary_window, "")
    if (primary) windows.push(primary)
    if (secondary) windows.push(secondary)
    windows.sort(function (a, b) { return a.windowSeconds - b.windowSeconds })

    if (windows.length === 1 && windows[0].label !== "session") {
        result.week = windows[0]
    } else if (windows.length > 0) {
        result.session = windows[0]
        if (windows.length > 1) result.week = windows[1]
    }

    var extras = data.additional_rate_limits
    if (Array.isArray(extras)) {
        for (var i = 0; i < extras.length; i++) {
            var group = extras[i] || {}
            var title = group.title || group.id || "Extra limit"
            var first = windowEntry(group.primary_window, title)
            var second = windowEntry(group.secondary_window, title)
            if (first) result.extraLimits.push(first)
            if (second) result.extraLimits.push(second)
        }
    }

    var review = windowEntry((data.code_review_rate_limit || {}).primary_window, "Code review")
    if (review) result.extraLimits.push(review)

    if (!result.session && !result.week && result.extraLimits.length === 0) {
        result.error = "No rate limit windows in Codex response"
        return result
    }

    result.ok = true
    return result
}
