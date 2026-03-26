# User Profile Component System

A modern, modular Vue 2 component system for displaying user profiles with provide/inject architecture, status batching, and cosmetic slot support.

## Features

- **Centralized Data Management**: `UserDataController` singleton handles all fetching, caching, normalization, and status batching
- **Provide/Inject Pattern**: Eliminates prop drilling - child components access data via injection
- **Modular Components**: Use individual components (avatar, name, badges, stats) or composed ones (card, profile)
- **Status Batching**: Automatic batch status requests to minimize API calls
- **Cosmetic Slots**: Extensible slots for future cosmetics system (banner overlays, avatar frames, username effects)
- **CSS Custom Properties**: Full theming support via CSS variables
- **Plain JavaScript**: No build tool required - works immediately

## Quick Start

### 1. Include Dependencies

Make sure Vue 2 and ColorfulLogger are loaded before the user components.

```html
<!-- In your base template -->
<script src="/static/js/vue.min.js"></script>
<script src="/static/js/logger.js"></script>
```

### 2. Include Component Files

Load in this order:

```html
<!-- Utilities first -->
<script src="/static/js/user/utils/constants.js"></script>
<script src="/static/js/user/utils/formatters.js"></script>

<!-- Core -->
<script src="/static/js/user/user-data-controller.js"></script>
<script src="/static/js/user/user-data-provider.js"></script>

<!-- Components -->
<script src="/static/js/user/components/user-avatar.js"></script>
<script src="/static/js/user/components/user-name.js"></script>
<script src="/static/js/user/components/user-badges.js"></script>
<script src="/static/js/user/components/user-status.js"></script>
<script src="/static/js/user/components/user-stats.js"></script>
<script src="/static/js/user/components/user-card.js"></script>
<script src="/static/js/user/components/user-profile.js"></script>
<script src="/static/js/user/components/index.js"></script>

<!-- CSS -->
<link rel="stylesheet" href="/static/css/components/user-profile.css">
```

### 3. Wrap Your App with Provider

Add `<user-data-provider>` at the root of your Vue app or wherever you need user data:

```html
<div id="app">
  <user-data-provider :auto-refresh-status="true">
    <!-- Your existing app content -->
    <navbar></navbar>
    <main>...</main>
  </user-data-provider>
</div>
```

### 4. Use Components

**Simple usage with user ID:**

```html
<user-card user-id="12345"></user-card>
```

**With pre-fetched user data:**

```html
<user-card :user="userDataObject"></user-card>
```

**Standalone components:**

```html
<user-avatar user-id="12345" size="large" show-status></user-avatar>
<user-name user-id="12345" show-country show-clan></user-name>
<user-badges :user="userData"></user-badges>
<user-stats :user="userData" :show="['pp', 'acc', 'plays', 'rank']"></user-stats>
<user-status :user="userData" show-text></user-status>
```

**Full profile with hover panel:**

```html
<user-profile 
  user-id="12345" 
  display-style="username"
  show-country
  show-clan
  show-badges
  show-status
  interactive>
</user-profile>
```

## Component Reference

### UserDataProvider

Top-level component that provides data to all children via provide/inject.

**Props:**
- `initialUsers` (Object) - Pre-fetched user data map (userId -> userData)
- `autoRefreshStatus` (Boolean) - Enable automatic status refresh (default: true)
- `statusRefreshInterval` (Number) - Refresh interval in ms (default: 30000)

**Provided APIs:**
- `getUserData(userId)` - Get cached user data
- `getStatusData(userId)` - Get cached status data
- `fetchUser(userId)` - Fetch user data (returns Promise)
- `fetchStatus(userId)` - Fetch status data (returns Promise)
- `subscribeToStatus(userId, callback)` - Subscribe to status updates
- `getAvatarUrl(user)`, `getBannerUrl(user)`, `getFlagUrl(country)`, etc.
- `formatNumber(num)`, `formatAccuracy(acc)`, `formatTimeAgo(date)`, etc.
- `isUserReady(userId)` - Check if user data is available

### UserAvatar

Displays a user's avatar image.

**Props:**
- `user` (String|Number|Object) - User ID or user data object
- `size` (String) - 'small', 'medium', 'large', 'xlarge' (default: 'medium')
- `showStatus` (Boolean) - Show status indicator ring (default: false)
- `linkToProfile` (Boolean) - Make avatar clickable (default: true)
- `customClass` (String) - Additional CSS classes

### UserName

Displays a user's name with optional country flag and clan tag.

**Props:**
- `user` (String|Number|Object) - User ID or user data object
- `showCountry` (Boolean) - Show country flag (default: false)
- `showClan` (Boolean) - Show clan tag (default: true)
- `linkToProfile` (Boolean) - Make name a link (default: true)
- `customClass` (String) - Additional CSS classes

### UserBadges

Displays a list of user badges with popup information.

**Props:**
- `user` (String|Number|Object) - User ID or user data object
- `badges` (Array) - Direct badge array (overrides user prop)
- `type` (Number) - 0 = regular with name, 1 = icon only (default: 0)
- `customClass` (String) - Additional CSS classes

### UserStatus

Displays a user's online status with optional text.

**Props:**
- `user` (String|Number|Object) - User ID or user data object
- `showText` (Boolean) - Show status text (default: true)
- `compact` (Boolean) - Show only indicator dot (default: false)
- `customClass` (String) - Additional CSS classes

### UserStats

Displays user statistics (PP, Accuracy, Plays, etc.).

**Props:**
- `user` (String|Number|Object) - User ID or user data object
- `mode` (Number) - Game mode (0-3, default: user's preferred mode)
- `show` (Array) - Which stats to display (default: ['pp', 'acc', 'plays'])
- `layout` (String) - 'horizontal', 'vertical', or 'compact' (default: 'horizontal')
- `customClass` (String) - Additional CSS classes

### UserCard

Composed card component combining avatar, name, badges, stats, and status.

**Props:**
- `user` (String|Number|Object) - User ID or user data object
- `showCountry` (Boolean) - Show country flag (default: true)
- `showClan` (Boolean) - Show clan tag (default: true)
- `showBadges` (Boolean) - Show badges (default: true)
- `showStatus` (Boolean) - Show status indicator (default: true)
- `mode` (Number) - Which mode's stats to show (default: preferred mode)
- `statsToShow` (Array) - Which stats to display (default: ['pp', 'acc', 'plays'])
- `customClass` (String) - Additional CSS classes

**Slots:**
- `banner-overlay` - Content overlaid on banner (for cosmetics)
- `avatar-frame` - Content around avatar frame (for cosmetics)
- `loading` - Custom loading state
- `error` - Custom error state
- `no-data` - Custom "no data" state

### UserProfile

Full-featured profile component with multiple display styles.

**Props:**
- `user` (String|Number|Object) - User ID or user data object
- `displayStyle` (String) - 'username', 'card', or 'search' (default: 'username')
- `showCountry` (Boolean) - Show country flag (default: false)
- `showClan` (Boolean) - Show clan tag (default: true)
- `showBadges` (Boolean) - Show badges (default: true)
- `showStatus` (Boolean) - Show status indicator (default: true)
- `interactive` (Boolean) - Enable hover/click interactions (default: true)
- `mode` (Number) - Which mode's stats to show
- `statsToShow` (Array) - Which stats to display
- `customClass` (String) - Additional CSS classes

**Slots:**
All slots from UserCard plus:
- `banner-overlay` - For username style hover panel banner
- `avatar-frame` - For username style avatar frame

## CSS Custom Properties

The system uses CSS custom properties for theming. Override these on the component or a parent:

```css
.user-profile-card {
  --user-banner: url(...);
  --user-accent: #ff5722;
  --status-playing: #2196F3;
  --avatar-border-radius: 12px;
  /* etc. */
}
```

See `user-profile.css` for the full list of available custom properties.

## Cosmetic Slots (Future-Proof)

Add custom content to these slots for cosmetics:

```html
<user-card user-id="12345">
  <!-- Banner effects (overlay) -->
  <template #banner-overlay>
    <div class="my-banner-effect"></div>
  </template>
  
  <!-- Avatar frame effects -->
  <template #avatar-frame>
    <div class="my-avatar-frame"></div>
  </template>
</user-card>
```

## Data Normalization

The `UserDataController` normalizes all API responses to a standard format:

```javascript
{
  info: {
    id: String,
    name: String,
    country: String,
    clan_id: String,
    clan_tag: String,
    badges: Array<{id, name, description, styles}>,
    preferred_mode: Number
  },
  stats: {
    '0': { pp, acc, plays, rank, country_rank, ... },
    '1': { ... },
    '2': { ... },
    '3': { ... }
  },
  raw: <original API response>
}
```

## Status Batching

The controller automatically batches status requests:
- Caches status for 5 minutes (configurable)
- Fetches in batches of 100 users (configurable)
- Periodic refresh every 30 seconds (configurable)
- Subscribe to updates for specific users

## Migration from Old System

The old `user-profile` component (from `userProfile.js`) is completely different. To migrate:

1. Replace `<user-profile>` with `<user-data-provider>` wrapper
2. Update props: `userid` → `user-id`, `displayStyle` → `display-style`, etc.
3. Remove all the method props (`:showProfile="showProfile"`, etc.) - these are now internal
4. Use slots for any custom content that was in the old templates

Example migration:

**Old:**
```html
<user-profile 
  userid="12345"
  display-style="card"
  :show-country="true"
  :show-clan="true"
  :show-badges="true"
  :show-status="true"
  :interactive="true"
  :avatar-url="avatarUrl"
  :banner-url="bannerUrl"
  :flag-url="flagUrl"
  :clan-url="clanUrl"
  :profile-url="profileUrl"
  :current-stats="currentStats"
  :format-number="formatNumber"
  :format-accuracy="formatAccuracy"
  :status-text="statusText"
  :status-classes="statusClasses"
  :status-string="statusString"
  :mouse-enter-panel="mouseEnterPanel"
  :mouse-leave-panel="mouseLeavePanel">
</user-profile>
```

**New:**
```html
<user-data-provider>
  <user-profile 
    user-id="12345"
    display-style="card"
    show-country
    show-clan
    show-badges
    show-status
    interactive>
  </user-profile>
</user-data-provider>
```

## API Endpoints Used

- `GET /api/v1/get_player_info?id={userId}&scope=all` - Fetch user data
- `GET /api/v1/get_player_status?id={userId}` - Fetch single user status
- `GET /api/v1/get_player_status?ids={id1},{id2},...` - Batch status fetch

## Browser Support

- Modern browsers with ES6 support
- Vue 2.x required
- No build step needed - works with plain `<script>` tags

## Performance Notes

- User data is cached for 5 minutes by default
- Status updates are batched to reduce API load
- Components only fetch data when actually rendered
- Provide/inject eliminates prop drilling overhead
- All components are tree-shakable if using a build tool

## License

Same as the main project.