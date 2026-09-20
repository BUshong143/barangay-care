/**
 * Barangay Care — Main JavaScript
 * Bottom nav, location map, photo preview, loaders (no blur), PH time display helpers.
 */

(function () {
    'use strict';

    // Flash dismiss
    function dismissFlash(el) {
        if (!el || el.classList.contains('flash-hide')) return;
        el.classList.add('flash-hide');
        el.addEventListener('animationend', function () { el.remove(); }, { once: true });
        setTimeout(function () { if (el.parentNode) el.remove(); }, 500);
    }
    document.querySelectorAll('.flash-close').forEach(function (btn) {
        btn.addEventListener('click', function () {
            dismissFlash(btn.closest('.flash-message'));
        });
    });
    document.querySelectorAll('.flash-message').forEach(function (el) {
        setTimeout(function () { dismissFlash(el); }, 6000);
    });

    // Dark mode toggle
    var themeToggle = document.getElementById('themeToggle');
    var themeToggleIcon = document.getElementById('themeToggleIcon');
    function syncThemeIcon() {
        var isDark = document.documentElement.classList.contains('dark-mode');
        if (themeToggleIcon) {
            themeToggleIcon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
        }
        if (themeToggle) {
            themeToggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
        }
    }
    if (themeToggle) {
        syncThemeIcon();
        themeToggle.addEventListener('click', function () {
            document.documentElement.classList.toggle('dark-mode');
            try {
                localStorage.setItem(
                    'theme',
                    document.documentElement.classList.contains('dark-mode') ? 'dark' : 'light'
                );
            } catch (e) {}
            syncThemeIcon();
        });
    }

    
    // Mobile theme FAB
    var mobileThemeToggle = document.getElementById('mobileThemeToggle');
    var mobileThemeIcon = document.getElementById('mobileThemeIcon');
    function syncMobileThemeIcon() {
        var isDark = document.documentElement.classList.contains('dark-mode');
        if (mobileThemeIcon) {
            mobileThemeIcon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
        }
        if (mobileThemeToggle) {
            mobileThemeToggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
        }
    }
    if (mobileThemeToggle) {
        syncMobileThemeIcon();
        mobileThemeToggle.addEventListener('click', function () {
            document.documentElement.classList.toggle('dark-mode');
            try {
                localStorage.setItem(
                    'theme',
                    document.documentElement.classList.contains('dark-mode') ? 'dark' : 'light'
                );
            } catch (e) {}
            syncMobileThemeIcon();
            if (typeof syncThemeIcon === 'function') syncThemeIcon();
            else if (themeToggleIcon) {
                var isDark = document.documentElement.classList.contains('dark-mode');
                themeToggleIcon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
            }
            if (typeof syncSettingsThemeUI === 'function') syncSettingsThemeUI();
        });
    }

    // Photo preview
    var photoInput = document.getElementById('photo');
    var filePlaceholder = document.getElementById('filePlaceholder');
    var filePreview = document.getElementById('filePreview');
    var previewImg = document.getElementById('previewImg');
    var removePhoto = document.getElementById('removePhoto');
    var fileUploadArea = document.getElementById('fileUploadArea');

    if (photoInput && filePreview && previewImg) {
        photoInput.addEventListener('change', function () {
            var file = photoInput.files && photoInput.files[0];
            if (!file) return;
            if (file.size > 5 * 1024 * 1024) {
                alert('File is too large. Maximum size is 5 MB.');
                photoInput.value = '';
                return;
            }
            var reader = new FileReader();
            reader.onload = function (e) {
                previewImg.src = e.target.result;
                if (filePlaceholder) filePlaceholder.classList.add('hidden');
                filePreview.classList.remove('hidden');
            };
            reader.readAsDataURL(file);
        });
        if (removePhoto) {
            removePhoto.addEventListener('click', function (e) {
                e.preventDefault();
                e.stopPropagation();
                photoInput.value = '';
                previewImg.src = '';
                filePreview.classList.add('hidden');
                if (filePlaceholder) filePlaceholder.classList.remove('hidden');
            });
        }
        if (fileUploadArea) {
            ['dragenter', 'dragover'].forEach(function (evt) {
                fileUploadArea.addEventListener(evt, function (e) {
                    e.preventDefault();
                    fileUploadArea.classList.add('dragover');
                });
            });
            ['dragleave', 'drop'].forEach(function (evt) {
                fileUploadArea.addEventListener(evt, function (e) {
                    e.preventDefault();
                    fileUploadArea.classList.remove('dragover');
                });
            });
            fileUploadArea.addEventListener('drop', function (e) {
                var files = e.dataTransfer && e.dataTransfer.files;
                if (files && files.length) {
                    photoInput.files = files;
                    photoInput.dispatchEvent(new Event('change'));
                }
            });
        }
    }

    // Form submit: button spinner + top progress bar only (no blur overlay)
    function attachSubmitLoader(formId, btnId) {
        var form = document.getElementById(formId);
        var btn = document.getElementById(btnId);
        if (!form) return;
        form.addEventListener('submit', function () {
            if (btn) {
                var text = btn.querySelector('.btn-text');
                var loader = btn.querySelector('.btn-loader');
                if (text) text.classList.add('hidden');
                if (loader) loader.classList.remove('hidden');
                btn.disabled = true;
            }
            showGlobalLoader();
        });
    }

    attachSubmitLoader('complaintForm', 'submitBtn');
    attachSubmitLoader('trackForm', 'trackBtn');
    attachSubmitLoader('confirmForm', 'confirmBtn');
    attachSubmitLoader('messageForm', 'msgBtn');
    attachSubmitLoader('loginForm', 'loginBtn');
    attachSubmitLoader('filterForm', 'filterBtn');

    document.querySelectorAll('.action-form').forEach(function (form) {
        form.addEventListener('submit', function () {
            showGlobalLoader();
            form.querySelectorAll('button[type="submit"]').forEach(function (b) {
                b.disabled = true;
            });
        });
    });

    // Copy tracking
    var copyBtn = document.getElementById('copyBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', function () {
            var el = document.getElementById('trackingNumber');
            if (!el) return;
            var text = el.textContent.trim();
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () {
                    copyBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied';
                    setTimeout(function () {
                        copyBtn.innerHTML = '<i class="fa-solid fa-copy"></i> Copy';
                    }, 2000);
                });
            }
        });
    }


    // Smooth transitions: hide any leftover loader ASAP
    hideGlobalLoader();
    window.addEventListener('pageshow', function () { hideGlobalLoader(); });

    // Light-touch nav: short progress bar only (no long lag feel)
    document.querySelectorAll('.bottom-nav a.bn-item, .nav-desktop a.nav-link, .nav-brand').forEach(function (a) {
        a.addEventListener('click', function (e) {
            var href = a.getAttribute('href');
            if (!href || href.charAt(0) === '#' || a.target === '_blank') return;
            // same-page hash only
            if (href === window.location.pathname + window.location.search) return;
            showGlobalLoader();
            // Safety: never leave the bar stuck if navigation is cancelled
            setTimeout(hideGlobalLoader, 2500);
        });
    });


    // Admin side nav (mobile drawer + desktop pin)
    var sideNav = document.getElementById('sideNav');
    var sideToggle = document.getElementById('sideNavToggle');
    var sideBackdrop = document.getElementById('sideNavBackdrop');
    var sidePin = document.getElementById('sideNavPin');
    function closeSideNav() {
        if (sideNav) sideNav.classList.remove('open');
        if (sideBackdrop) sideBackdrop.hidden = true;
    }
    function openSideNav() {
        if (sideNav) sideNav.classList.add('open');
        if (sideBackdrop) sideBackdrop.hidden = false;
    }
    if (sideToggle) {
        sideToggle.addEventListener('click', function () {
            if (sideNav && sideNav.classList.contains('open')) closeSideNav();
            else openSideNav();
        });
    }
    if (sideBackdrop) sideBackdrop.addEventListener('click', closeSideNav);
    document.querySelectorAll('.side-link').forEach(function (a) {
        a.addEventListener('click', function () {
            if (window.innerWidth <= 900) closeSideNav();
            showGlobalLoader();
            setTimeout(hideGlobalLoader, 2500);
        });
    });

    // Desktop: pin / unpin sidebar (Aether-style)
    if (sidePin) {
        sidePin.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            var pinned = document.documentElement.classList.toggle('sidebar-pinned');
            try {
                localStorage.setItem('sidebarPinned', pinned ? '1' : '0');
            } catch (err) {}
            sidePin.setAttribute('aria-label', pinned ? 'Unpin sidebar' : 'Pin sidebar open');
            sidePin.setAttribute('title', pinned ? 'Unpin sidebar' : 'Pin sidebar open');
        });
        // Sync initial aria
        if (document.documentElement.classList.contains('sidebar-pinned')) {
            sidePin.setAttribute('aria-label', 'Unpin sidebar');
            sidePin.setAttribute('title', 'Unpin sidebar');
        }
    }

    // Mobile topbar theme button mirrors main toggle
    var themeMobile = document.getElementById('themeToggleMobile');
    if (themeMobile && themeToggle) {
        themeMobile.addEventListener('click', function () { themeToggle.click(); });
        // keep icon in sync
        var mo = new MutationObserver(function () {
            var ic = themeMobile.querySelector('i');
            if (ic && themeToggleIcon) ic.className = themeToggleIcon.className;
        });
        if (themeToggleIcon) mo.observe(themeToggleIcon, { attributes: true, attributeFilter: ['class'] });
    }


    // Settings page theme toggle (desktop primary control)
    var settingsThemeBtn = document.getElementById('settingsThemeToggle');
    var settingsThemeIcon = document.getElementById('settingsThemeIcon');
    var settingsThemeLabel = document.getElementById('settingsThemeLabel');
    function syncSettingsThemeUI() {
        var isDark = document.documentElement.classList.contains('dark-mode');
        if (settingsThemeIcon) {
            settingsThemeIcon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
        }
        if (settingsThemeLabel) {
            settingsThemeLabel.textContent = isDark ? 'Switch to light mode' : 'Switch to dark mode';
        }
    }
    if (settingsThemeBtn) {
        syncSettingsThemeUI();
        settingsThemeBtn.addEventListener('click', function () {
            document.documentElement.classList.toggle('dark-mode');
            try {
                localStorage.setItem(
                    'theme',
                    document.documentElement.classList.contains('dark-mode') ? 'dark' : 'light'
                );
            } catch (e) {}
            syncSettingsThemeUI();
            if (typeof syncThemeIcon === 'function') syncThemeIcon();
            else if (themeToggleIcon) {
                var isDark = document.documentElement.classList.contains('dark-mode');
                themeToggleIcon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
            }
        });
    }

    // Home dashboard
    if (document.getElementById('statsGrid')) {
        loadStats();
        loadRecent();
    }

    // Geolocation + map on submit page
    initLocationMap();

    // Static maps on track / admin detail
    initStaticMaps();
    if (document.getElementById("adminMap")) { initAdminRouteMap(); }
})();

function showGlobalLoader() {
    var bar = document.getElementById('global-loader');
    if (bar) {
        bar.classList.remove('hidden');
        bar.setAttribute('aria-hidden', 'false');
    }
}

function hideGlobalLoader() {
    var bar = document.getElementById('global-loader');
    if (bar) {
        bar.classList.add('hidden');
        bar.setAttribute('aria-hidden', 'true');
    }
}

/* ===== Geolocation + map (GPS primary; works on HTTPS when deployed) ===== */
var submitMap = null;
var submitMarker = null;

function isSecureContextForGeo() {
    try {
        if (window.isSecureContext) return true;
    } catch (e) {}
    var h = location.hostname || '';
    return location.protocol === 'https:' ||
        h === 'localhost' ||
        h === '127.0.0.1' ||
        h === '[::1]';
}



/* Pulsing circle location marker (all maps / roles) */
function pulseCircleIcon() {
    return L.divIcon({
        className: 'pulse-marker-wrap',
        html: '<div class="pulse-marker"><span class="pulse-ring"></span><span class="pulse-ring pulse-ring-delay"></span><span class="pulse-core"></span></div>',
        iconSize: [28, 28],
        iconAnchor: [14, 14],
        popupAnchor: [0, -14]
    });
}

/* Free OSM tiles + CSS mono face (no API key, no watermark) */
function addMapBaseLayers(map, preferSatellite) {
    if (!map || typeof L === 'undefined') return null;

    // OpenStreetMap — free, no API key
    var mono = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap'
    });
    var street = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap'
    });
    var satellite = L.tileLayer(
        'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
        {
            maxZoom: 18,
            maxNativeZoom: 17,
            attribution: 'Tiles &copy; Esri'
        }
    );

    if (preferSatellite) {
        satellite.addTo(map);
        try {
            var c0 = map.getContainer();
            if (c0) c0.classList.remove('map-face-mono');
        } catch (e) {}
    } else {
        mono.addTo(map);
        try {
            var c = map.getContainer();
            if (c) c.classList.add('map-face-mono');
        } catch (e) {}
    }

    try {
        var layersCtrl = L.control.layers(
            {
                'Mono': mono,
                'Street': street,
                'Satellite': satellite
            },
            null,
            { position: 'topright', collapsed: true }
        );
        layersCtrl.addTo(map);
        var el = layersCtrl.getContainer();
        if (el) {
            el.classList.add('map-layers-enhanced');
            // Iconify labels after Leaflet builds them
            el.querySelectorAll('.leaflet-control-layers-base label').forEach(function (lab) {
                var txt = (lab.textContent || '').trim();
                var icon = 'fa-circle-half-stroke';
                if (txt.indexOf('Street') >= 0) icon = 'fa-road';
                if (txt.indexOf('Satellite') >= 0) icon = 'fa-globe';
                var span = lab.querySelector('span');
                if (!span) {
                    // structure: input + text node
                    var nodes = Array.prototype.slice.call(lab.childNodes);
                    nodes.forEach(function (n) {
                        if (n.nodeType === 3 && n.textContent.trim()) {
                            var s = document.createElement('span');
                            s.className = 'map-layer-opt';
                            s.innerHTML = '<i class="fa-solid ' + icon + '"></i> ' + n.textContent.trim();
                            lab.replaceChild(s, n);
                        }
                    });
                }
            });
        }
    } catch (e) {}

    function applyMonoFace(on) {
        var c = map.getContainer();
        if (!c) return;
        if (on) c.classList.add('map-face-mono');
        else c.classList.remove('map-face-mono');
        // force tile redraw so filter applies/removes cleanly
        setTimeout(function () {
            try { map.invalidateSize(); } catch (err) {}
        }, 50);
    }

    map.on('baselayerchange', function (e) {
        var name = (e && e.name) ? String(e.name) : '';
        var isMono = name === 'Mono' || name.indexOf('Mono') >= 0;
        applyMonoFace(isMono);
        // ensure only the selected base is visible
        if (isMono) {
            if (map.hasLayer(street)) map.removeLayer(street);
            if (map.hasLayer(satellite)) map.removeLayer(satellite);
            if (!map.hasLayer(mono)) map.addLayer(mono);
        }
    });
    return { mono: mono, street: street, satellite: satellite };
}

function addSatelliteLayers(map) {
    return addMapBaseLayers(map, false);
}

function initStaticMaps() {
    if (typeof L === 'undefined') return;
    var trackMap = document.getElementById('trackMap');
    if (trackMap) {
        var lat = Number(trackMap.getAttribute('data-lat'));
        var lng = Number(trackMap.getAttribute('data-lng'));
        if (isFinite(lat) && isFinite(lng)) {
            try {
                var map = L.map(trackMap, { scrollWheelZoom: false }).setView([lat, lng], 17);
                addSatelliteLayers(map);
                L.marker([lat, lng], { icon: pulseCircleIcon() }).addTo(map)
                    .bindPopup('Report location').openPopup();
                setTimeout(function () { map.invalidateSize(); }, 200);
            } catch (err) {
                console.warn('trackMap init failed', err);
            }
        }
    }
}

function initLocationMap() {
    var btn = document.getElementById('btnLocate');
    if (!btn) return;

    btn.addEventListener('click', function () {
        requestDeviceLocation(true);
    });
}

function requestDeviceLocation(fromButton) {
    var hint = document.getElementById('locationHint');
    var btn = document.getElementById('btnLocate');
    var btnText = document.getElementById('locateBtnText');

    if (!navigator.geolocation) {
        if (hint) {
            hint.textContent = 'Geolocation is not supported by this browser. You can still submit without a map pin.';
            hint.style.color = '#d97706';
        }
        return;
    }

    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = 'Getting your location…';
    if (hint) {
        if (isSecureContextForGeo()) {
            hint.textContent = 'Please allow location access when prompted by your browser.';
            hint.style.color = '';
        } else {
            hint.textContent = 'Trying to get your location… On local network HTTP, some browsers block GPS until the site uses HTTPS.';
            hint.style.color = '';
        }
    }

    navigator.geolocation.getCurrentPosition(
        function (pos) {
            var lat = pos.coords.latitude;
            var lng = pos.coords.longitude;
            if (!isFinite(lat) || !isFinite(lng)) {
                onGeoError({ code: 2 });
                return;
            }
            setLocationOnForm(lat, lng);
            showSubmitMap(lat, lng);
            if (btn) btn.disabled = false;
            if (btnText) btnText.textContent = 'Update my location';
            if (hint) {
                hint.textContent = 'Location set. Drag the pin to adjust if needed.';
                hint.style.color = '#059669';
            }
        },
        function (err) {
            onGeoError(err);
        },
        {
            enableHighAccuracy: true,
            timeout: 15000,
            maximumAge: 0
        }
    );

    function onGeoError(err) {
        if (btn) btn.disabled = false;
        if (btnText) btnText.textContent = 'Allow access to my location';
        var msg = 'Could not get location. ';
        var code = err && err.code;
        if (code === 1) {
            msg = 'Location permission denied. Enable location for this site in browser settings, then try again.';
            if (!isSecureContextForGeo()) {
                msg = 'GPS needs a secure site (HTTPS) when using a phone on LAN. After deployment with HTTPS, this button will work. You can still submit without a pin.';
            }
        } else if (code === 2) {
            msg = 'Position unavailable. Check that GPS/location is on, then try again.';
        } else if (code === 3) {
            msg = 'Location request timed out. Move to an open area and try again.';
        } else {
            msg = 'Could not get location. Try again, or submit without a map pin.';
        }
        if (hint) {
            hint.textContent = msg;
            hint.style.color = '#dc2626';
        }
    }
}

function setLocationOnForm(lat, lng) {
    var la = Number(lat);
    var ln = Number(lng);
    if (!isFinite(la) || !isFinite(ln)) return;
    var latInput = document.getElementById('latitude');
    var lngInput = document.getElementById('longitude');
    if (latInput) latInput.value = la.toFixed(7);
    if (lngInput) lngInput.value = ln.toFixed(7);
    var coordsEl = document.getElementById('mapCoords');
    if (coordsEl) coordsEl.textContent = la.toFixed(6) + ', ' + ln.toFixed(6);
}

function showSubmitMap(lat, lng) {
    var container = document.getElementById('mapContainer');
    var mapEl = document.getElementById('map');
    if (!container || !mapEl || typeof L === 'undefined') return;

    var la = Number(lat);
    var ln = Number(lng);
    if (!isFinite(la) || !isFinite(ln)) return;

    container.classList.remove('hidden');

    try {
        if (!submitMap) {
            submitMap = L.map(mapEl).setView([la, ln], 16);
            addSatelliteLayers(submitMap);

            submitMarker = L.marker([la, ln], { draggable: true, icon: pulseCircleIcon() }).addTo(submitMap);
            submitMarker.on('dragend', function () {
                if (!submitMarker) return;
                var p = submitMarker.getLatLng();
                setLocationOnForm(p.lat, p.lng);
            });

            // Optional: tap map to move pin
            submitMap.on('click', function (e) {
                if (!e || !e.latlng || !submitMap || !submitMarker) return;
                try {
                    submitMarker.setLatLng(e.latlng);
                    setLocationOnForm(e.latlng.lat, e.latlng.lng);
                } catch (err) {
                    console.warn('Pin move failed', err);
                }
            });

            setTimeout(function () { if (submitMap) submitMap.invalidateSize(); }, 200);
            setTimeout(function () { if (submitMap) submitMap.invalidateSize(); }, 500);
        } else {
            submitMap.setView([la, ln], 16);
            if (submitMarker) {
                submitMarker.setLatLng([la, ln]);
            } else {
                submitMarker = L.marker([la, ln], { draggable: true, icon: pulseCircleIcon() }).addTo(submitMap);
                submitMarker.on('dragend', function () {
                    var p = submitMarker.getLatLng();
                    setLocationOnForm(p.lat, p.lng);
                });
            }
            submitMap.invalidateSize();
        }
    } catch (err) {
        console.warn('Map error', err);
    }
}


function categoryIcon(cat) {
    var map = {
        'road': 'fa-road', 'roads': 'fa-road',
        'garbage': 'fa-trash', 'waste': 'fa-trash',
        'water': 'fa-faucet-drip', 'drainage': 'fa-water',
        'electricity': 'fa-bolt', 'power': 'fa-bolt',
        'peace and order': 'fa-shield-halved', 'safety': 'fa-shield-halved',
        'noise': 'fa-volume-high',
        'street light': 'fa-lightbulb', 'streetlight': 'fa-lightbulb',
        'health': 'fa-briefcase-medical',
        'animal': 'fa-paw',
        'other': 'fa-circle-exclamation'
    };
    var key = (cat || '').toLowerCase().trim();
    return map[key] || 'fa-clipboard-list';
}

function loadStats() {
    var grid = document.getElementById('statsGrid');
    if (!grid) return;
    fetch('/api/stats')
        .then(function (res) { return res.json(); })
        .then(function (json) {
            if (!json.success || !json.data) return;
            var d = json.data;
            setText('stat-total', d.total);
            setText('stat-submitted', d.submitted);
            setText('stat-in-progress', d.in_progress);
            setText('stat-resolved', d.resolved);
            setText('stat-confirmed', d.confirmed);
            if (document.getElementById('stat-urgent')) {
                setText('stat-urgent', d.urgent);
            }
        })
        .catch(function () { /* keep server-rendered defaults */ });
}

function loadRecent() {
    var grid = document.getElementById('recentBody');
    if (!grid) return;
    fetch('/api/complaints?limit=10')
        .then(function (res) { return res.json(); })
        .then(function (json) {
            if (json.success && json.data && json.data.length) {
                grid.innerHTML = json.data.map(function (c) {
                    return '<div class="record-card">' +
                        '<div class="record-card-top">' +
                        '<div class="record-icon"><i class="fa-solid ' + categoryIcon(c.category) + '"></i></div>' +
                        '<span class="badge badge-status-' + statusClass(c.status) + '">' +
                        escapeHtml(c.status) + '</span>' +
                        '</div>' +
                        '<div class="record-tracking">' + escapeHtml(c.tracking_number) + '</div>' +
                        '<div class="record-category">' + escapeHtml(c.category) + '</div>' +
                        '<div class="record-card-bottom">' +
                        '<span class="badge badge-' + (c.priority || '').toLowerCase() + '">' +
                        escapeHtml(c.priority) + '</span>' +
                        '<span class="record-date">' + formatDatePH(c.created_at) + '</span>' +
                        '</div>' +
                        '</div>';
                }).join('');
            } else {
                grid.innerHTML = '<div class="records-empty">No complaints yet.</div>';
            }
        })
        .catch(function () {
            grid.innerHTML = '<div class="records-empty">Failed to load records.</div>';
        });
}

function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val != null ? val : '0';
}

function statusClass(s) {
    return (s || '').toLowerCase().replace(/\s+/g, '-');
}

/** Format ISO date in Philippines time (Asia/Manila) */
function formatDatePH(iso) {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleString('en-PH', {
            timeZone: 'Asia/Manila',
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
    } catch (e) {
        return iso;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

window.showGlobalLoader = showGlobalLoader;
window.hideGlobalLoader = hideGlobalLoader;


/**
 * Admin / assigned personnel map: complaint pin, motorcycle marker, OSRM route line.
 */
function initAdminRouteMap() {
    var el = document.getElementById('adminMap');
    if (!el || typeof L === 'undefined') return;
    // Guard against double-initialization (Leaflet throws if a container
    // already has a map instance attached to it).
    if (el._leaflet_id) return;

    var destLat = parseFloat(el.getAttribute('data-lat'));
    var destLng = parseFloat(el.getAttribute('data-lng'));
    if (isNaN(destLat) || isNaN(destLng)) return;

    var map = L.map(el).setView([destLat, destLng], 15);
    addSatelliteLayers(map);

    var complaintIcon = pulseCircleIcon();

    var motorIcon = L.divIcon({
        className: 'map-marker-motor',
        html: '<i class="fa-solid fa-motorcycle motor-icon-plain" aria-hidden="true"></i>',
        iconSize: [28, 28],
        iconAnchor: [14, 14],
        popupAnchor: [0, -12]
    });

    var destMarker = L.marker([destLat, destLng], { icon: complaintIcon })
        .addTo(map)
        .bindPopup('<strong>Complaint</strong><br>' + (el.getAttribute('data-tracking') || '') +
            '<br>' + (el.getAttribute('data-location') || ''));

    var staffMarker = null;
    var routeLine = null;
    var statusEl = document.getElementById('routeStatus');

    function setStatus(msg, isError) {
        if (!statusEl) return;
        statusEl.innerHTML = msg;
        statusEl.style.color = isError ? '#dc2626' : '#475569';
    }

    function clearRoute() {
        if (routeLine) {
            map.removeLayer(routeLine);
            routeLine = null;
        }
    }

    function drawRoute(fromLat, fromLng) {
        clearRoute();
        if (staffMarker) {
            staffMarker.setLatLng([fromLat, fromLng]);
        } else {
            staffMarker = L.marker([fromLat, fromLng], { icon: motorIcon })
                .addTo(map)
                .bindPopup('<strong>Assigned personnel</strong><br>Your current position');
        }

        setStatus('Calculating driving route…');

        var url = 'https://router.project-osrm.org/route/v1/driving/' +
            fromLng + ',' + fromLat + ';' + destLng + ',' + destLat +
            '?overview=full&geometries=geojson';

        fetch(url)
            .then(function (res) { return res.json(); })
            .then(function (data) {
                if (!data.routes || !data.routes.length) {
                    setStatus('No driving route found. You can still use Google Maps.', true);
                    map.fitBounds(L.latLngBounds([[fromLat, fromLng], [destLat, destLng]]), { padding: [40, 40] });
                    return;
                }
                var route = data.routes[0];
                var coords = route.geometry.coordinates.map(function (c) {
                    return [c[1], c[0]];
                });
                routeLine = L.polyline(coords, {
                    color: '#f59e0b',
                    weight: 5,
                    opacity: 0.95,
                    lineJoin: 'round',
                    lineCap: 'round'
                }).addTo(map);
                // Directional arrow tips along the path
                try {
                    if (coords.length >= 2) {
                        var mid = coords[Math.floor(coords.length / 2)];
                        var prev = coords[Math.max(0, Math.floor(coords.length / 2) - 1)];
                        var bearing = Math.atan2(mid[1] - prev[1], mid[0] - prev[0]) * 180 / Math.PI;
                        L.marker(mid, {
                            interactive: false,
                            icon: L.divIcon({
                                className: 'route-arrow-wrap',
                                html: '<div class="route-arrow" style="transform:rotate(' + bearing + 'deg)">▶</div>',
                                iconSize: [16, 16],
                                iconAnchor: [8, 8]
                            })
                        }).addTo(map);
                    }
                } catch (err) {}
                map.fitBounds(routeLine.getBounds(), { padding: [40, 40], maxZoom: 17 });

                var km = (route.distance / 1000);
                var mins = Math.round(route.duration / 60);
                if (km < 0.05) {
                    setStatus(
                        '<i class="fa-solid fa-motorcycle"></i> You are very close to the complaint pin (under 50 m). Orange line shows the path.'
                    );
                } else {
                    setStatus(
                        '<i class="fa-solid fa-motorcycle"></i> Route ready: <strong>' + km.toFixed(2) +
                        ' km</strong> · about <strong>' + mins +
                        ' min</strong> drive. Orange line = path to complaint.'
                    );
                }

                // Update Google Maps link to include origin
                var gBtn = document.getElementById('btnOpenGoogleMaps');
                if (gBtn) {
                    gBtn.href = 'https://www.google.com/maps/dir/?api=1&origin=' +
                        fromLat + ',' + fromLng +
                        '&destination=' + destLat + ',' + destLng +
                        '&travelmode=driving';
                }
            })
            .catch(function () {
                setStatus('Could not reach routing service. Use Open in Google Maps instead.', true);
                map.fitBounds(L.latLngBounds([[fromLat, fromLng], [destLat, destLng]]), { padding: [40, 40] });
            });
    }

    var btn = document.getElementById('btnRouteToComplaint');
    if (btn) {
        btn.addEventListener('click', function () {
            if (!navigator.geolocation) {
                setStatus('Geolocation is not supported on this device.', true);
                return;
            }
            btn.disabled = true;
            setStatus('Getting your GPS position…');
            navigator.geolocation.getCurrentPosition(
                function (pos) {
                    btn.disabled = false;
                    drawRoute(pos.coords.latitude, pos.coords.longitude);
                },
                function (err) {
                    btn.disabled = false;
                    var msg = 'Could not get your location. ';
                    if (err.code === 1) msg += 'Allow location permission, or open via localhost/HTTPS.';
                    else msg += 'Try again or use Google Maps.';
                    setStatus(msg, true);
                },
                { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
            );
        });
    }

    setTimeout(function () { map.invalidateSize(); }, 250);
}

window.initAdminRouteMap = initAdminRouteMap;
