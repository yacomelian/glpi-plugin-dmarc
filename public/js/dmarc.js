/**
 * DMARC plugin for GLPI: charts of the dashboard (ECharts, loaded by GLPI).
 * @license GPLv2+
 */
(function () {
    'use strict';

    function ready(fn) {
        if (document.readyState !== 'loading') {
            fn();
        } else {
            document.addEventListener('DOMContentLoaded', fn);
        }
    }

    // texts come translated from the page (#dmarc-i18n); numbers in the page language
    var t = {};
    try {
        var i18n = document.getElementById('dmarc-i18n');
        t = i18n ? JSON.parse(i18n.textContent || '{}') : {};
    } catch (e) {
        t = {};
    }
    function tr(key) {
        return t[key] || key;
    }
    var nf = new Intl.NumberFormat(document.documentElement.lang || undefined);
    var nf1 = new Intl.NumberFormat(document.documentElement.lang || undefined, { minimumFractionDigits: 1, maximumFractionDigits: 1 });

    // names come from the reports (attacker-controlled): plain text only
    function text(v) {
        return String(v == null ? '' : v).replace(/[<>&"']/g, '');
    }
    var colors = {
        pass: '#2fb344', none: '#f59f00', quarantine: '#f76707', reject: '#d63939',
        dkim: '#4299e1', spf: '#ae3ec9', line: '#206bc4', muted: '#9aa0ac'
    };

    function dark() {
        var t = document.documentElement.getAttribute('data-bs-theme') || document.body.getAttribute('data-bs-theme');
        return t === 'dark';
    }

    function label(bucket) {
        var p = String(bucket).split('-');
        return p.length === 3 ? p[2] + '/' + p[1] + '/' + p[0].slice(2) : bucket;
    }

    function base() {
        return {
            backgroundColor: 'transparent',
            textStyle: { fontFamily: 'inherit' },
            grid: { left: 50, right: 20, top: 40, bottom: 50, containLabel: true },
            tooltip: { trigger: 'axis', valueFormatter: function (v) { return v == null ? '' : nf.format(v); } },
            legend: { top: 0 }
        };
    }

    var builders = {
        volume: function (c) {
            var o = base();
            o.xAxis = { type: 'category', data: c.rows.map(function (r) { return label(r.bucket); }) };
            o.yAxis = { type: 'value', axisLabel: { formatter: function (v) { return nf.format(v); } } };
            o.dataZoom = c.rows.length > 60 ? [{ type: 'inside' }, { type: 'slider', height: 18, bottom: 5 }] : [];
            o.series = [
                { name: tr('pass'), key: 'pass', color: colors.pass },
                { name: tr('fail_none'), key: 'fail_none', color: colors.none },
                { name: tr('fail_quarantine'), key: 'quarantine', color: colors.quarantine },
                { name: tr('fail_reject'), key: 'reject', color: colors.reject }
            ].map(function (s) {
                return {
                    name: s.name, type: 'bar', stack: 'v', color: s.color, barMaxWidth: 28,
                    emphasis: { focus: 'series' },
                    data: c.rows.map(function (r) { return r[s.key]; })
                };
            });
            return o;
        },
        compliance: function (c) {
            var o = base();
            o.tooltip.valueFormatter = function (v) { return v == null ? '' : nf1.format(v) + ' %'; };
            o.xAxis = { type: 'category', data: c.rows.map(function (r) { return label(r.bucket); }) };
            o.yAxis = { type: 'value', min: 0, max: 100, axisLabel: { formatter: '{value} %' } };
            o.dataZoom = c.rows.length > 60 ? [{ type: 'inside' }, { type: 'slider', height: 18, bottom: 5 }] : [];
            o.series = [
                { name: tr('pass_dmarc'), key: 'pass_pct', color: colors.pass },
                { name: tr('dkim_aligned'), key: 'dkim_pct', color: colors.dkim },
                { name: tr('spf_aligned'), key: 'spf_pct', color: colors.spf }
            ].map(function (s) {
                return {
                    name: s.name, type: 'line', smooth: true, showSymbol: false, color: s.color, connectNulls: false,
                    data: c.rows.map(function (r) { return r.total > 0 ? Math.round(r[s.key] * 10) / 10 : null; })
                };
            });
            return o;
        },
        causes: function (c) {
            var palette = ['#2fb344', '#74b816', '#a9d96c', '#4299e1', '#f59f00', '#f76707', '#ae3ec9', '#d63939'];
            return {
                backgroundColor: 'transparent',
                tooltip: { trigger: 'item', valueFormatter: function (v) { return nf.format(v); } },
                legend: { type: 'plain', bottom: 0, itemWidth: 12, itemHeight: 10, textStyle: { fontSize: 11 } },
                series: [{
                    type: 'pie', radius: ['32%', '55%'], center: ['50%', '36%'], avoidLabelOverlap: true,
                    label: { show: false },
                    data: c.rows.map(function (r, i) {
                        return { name: text(r.name), value: r.value, itemStyle: { color: palette[i % palette.length] } };
                    })
                }]
            };
        },
        bars: function (c) {
            var rows = c.rows.slice().reverse();
            var o = base();
            o.legend = { show: false };
            o.grid = { left: 10, right: 30, top: 10, bottom: 10, containLabel: true };
            o.tooltip.trigger = 'axis';
            o.xAxis = { type: 'value', axisLabel: { formatter: function (v) { return nf.format(v); } } };
            o.yAxis = { type: 'category', data: rows.map(function (r) { return text(r.name); }) };
            o.series = [{ type: 'bar', name: tr('messages'), color: colors.line, data: rows.map(function (r) { return r.value; }) }];
            return o;
        },
        senders: function (c) {
            var rows = c.rows.slice().reverse();
            var o = base();
            o.grid = { left: 10, right: 30, top: 30, bottom: 10, containLabel: true };
            o.xAxis = { type: 'value', axisLabel: { formatter: function (v) { return nf.format(v); } } };
            o.yAxis = { type: 'category', data: rows.map(function (r) { return text(r.sender); }) };
            o.series = [
                { name: tr('pass'), type: 'bar', stack: 's', color: colors.pass, data: rows.map(function (r) { return r.pass; }) },
                { name: tr('fail'), type: 'bar', stack: 's', color: colors.reject, data: rows.map(function (r) { return r.total - r.pass; }) }
            ];
            return o;
        }
    };

    // Domain selector: the checked boxes go to the hidden "domain" field
    // ("a.es,b.es"; all checked = no filter, so new domains show up too)
    ready(function () {
        var box = document.getElementById('dmarc-domains');
        var field = document.getElementById('dmarc-domain');
        if (!box || !field) {
            return;
        }
        var checks = box.querySelectorAll('input.dmarc-dom');
        function sync() {
            var on = [];
            checks.forEach(function (c) { if (c.checked) { on.push(c.value); } });
            field.value = on.length === checks.length ? '' : on.join(',');
            if (on.length === 0) {
                field.value = '';
            }
        }
        checks.forEach(function (c) { c.addEventListener('change', sync); });
        box.querySelectorAll('[data-dmarc-dom]').forEach(function (a) {
            a.addEventListener('click', function (e) {
                e.preventDefault();
                var all = a.getAttribute('data-dmarc-dom') === 'all';
                checks.forEach(function (c) {
                    if (!c.closest('[data-dmarc-dom-item]').classList.contains('d-none')) {
                        c.checked = all;
                    }
                });
                sync();
            });
        });
        var search = box.querySelector('[data-dmarc-dom-search]');
        if (search) {
            search.addEventListener('input', function () {
                var t = search.value.trim().toLowerCase();
                box.querySelectorAll('[data-dmarc-dom-item]').forEach(function (i) {
                    i.classList.toggle('d-none', t !== '' && i.getAttribute('data-dmarc-dom-item').indexOf(t) === -1);
                });
            });
            search.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); } });
        }
        // the form may be sent with none checked: tell instead of showing everything
        box.closest('form').addEventListener('submit', function (e) {
            var any = false;
            checks.forEach(function (c) { any = any || c.checked; });
            if (!any) {
                e.preventDefault();
                window.alert(tr('select_domain'));
            }
        });
    });

    // "Recogida" tab: while a background job runs, reload every 10 s
    ready(function () {
        var w = document.getElementById('dmarc-worker');
        if (w && w.getAttribute('data-running') === '1') {
            window.setTimeout(function () { window.location.reload(); }, 10000);
        }
    });

    ready(function () {
        var el = document.getElementById('dmarc-charts');
        if (!el || typeof window.echarts === 'undefined') {
            return;
        }
        var charts = {};
        try {
            charts = JSON.parse(el.textContent || '{}');
        } catch (e) {
            return;
        }
        var instances = [];
        document.querySelectorAll('.dmarc-chart[data-chart]').forEach(function (node) {
            var def = charts[node.getAttribute('data-chart')];
            if (!def || !builders[def.type]) {
                return;
            }
            if (!def.rows || def.rows.length === 0) {
                var empty = document.createElement('div');
                empty.className = 'text-muted small p-3';
                empty.textContent = tr('no_data');
                node.replaceChildren(empty);
                node.style.height = 'auto';
                return;
            }
            var chart = window.echarts.init(node, dark() ? 'dark' : null);
            chart.setOption(builders[def.type](def));
            instances.push(chart);
        });
        window.addEventListener('resize', function () {
            instances.forEach(function (c) { c.resize(); });
        });
    });
})();
