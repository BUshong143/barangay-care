# Barangay Care — UX/UI Redesign Notes

Completed phases 1–10 per `barangay-care-redesign-brief.md`.

## What changed

### Design system (`static/css/style.css`)
- Semantic tokens: `--background`, `--surface`, `--border`, `--text-primary/secondary/muted`, `--space-1…6`, `--primary-hover`, `--info`
- Dark mode remaps the same tokens
- New components: wizard, status timeline, status pills, summary row, complaint list, notif feed, admin table, map layout, skeletons, empty/error states, responsive pass

### Navigation (`templates/base.html`)
- Admin sidebar grouped: Main / Management / Reports / System
- Mobile drawer toggle + backdrop wired
- Public desktop top bar
- Resident vs guest bottom nav
- Skip-to-content link; `main#main-content`

### Resident
- Home: calmer hero, 4 metrics
- Dashboard: welcome, primary CTA, summary, list rows (template ready; route may still redirect)
- Login/register: auth cards
- Submit: 4-step wizard (same POST/fields)
- Success / duplicate screens cleaned
- Track: visual timeline; push script unchanged
- Notifications: day groups + unread markers

### Admin
- Login auth card
- Dashboard: needs-attention first; charts in `<details>`
- Cases list: filters toggle; table + mobile list
- Complaint detail: two-column sticky actions
- Map, reports, categories, staff, activity, restore, settings restyled

### Preserved
- All routes, form field names, element IDs used by JS
- Push/SW flow on `track.html`
- Chart.js canvas IDs
- Backend logic (no production DB/deploy changes)

## Deploy
Copy updated `static/` and `templates/` (and this tree) over your app. Bump static cache query (`?v=49` in base) if CDN/browser cache is sticky.
