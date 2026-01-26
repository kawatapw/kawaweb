bootstrapVue('admin-users-panel', {
    el: "#users",
    delimiters: ["<%", "%>"],
    data() {
        return {
            flags: window.flags,
            users: JSON.parse(users || '[]'), // Initialize with server data
            page: parseInt(page) || 1,
            totalPages: parseInt(totalPages) || 1,
            totalCount: parseInt(totalCount) || 0,
            userquery: userquery || '', // Initialize with server search
            sortBy: sortBy || 'id',
            sortOrder: sortOrder || 'ASC',
            filterPriv: filterPriv && filterPriv !== 'None' ? filterPriv : '',
            filterCountry: filterCountry || '',
            load: false,
            playersLoading: false,
            searchTimeout: null,
        }
    },
    created() {
        if(!this.$log) {
            this.$log = ColorfulLogger.child('Admin | Users Page');
        }
    },
    methods: {
        handleUserInput() {
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => {
                this.page = 1; // Reset to first page when searching
                this.loadUsers();
            }, 500);
        },
        loadUsers() {
            this.playersLoading = true;
            const params = new URLSearchParams({
                update: 'true',
                search: this.userquery,
                sort: this.sortBy,
                order: this.sortOrder,
                priv: this.filterPriv,
                country: this.filterCountry
            });

            const url = `/admin/users/${this.page}?${params.toString()}`;

            // Debug logs - using global kawataLogger with sections
            this.$log.debug('LIFECYCLE', 'Users.js User Page Created');
            this.$log.debug('DATA', 'Initial users:', this.users);
            this.$log.debug('DATA', 'Page:', this.page, 'Total Pages:', this.totalPages);

            fetch(url)
                .then(response => response.json())
                .then(data => {
                    if (data.users) {
                        this.users = data.users;
                        this.totalPages = data.pagination.total_pages;
                        this.totalCount = data.pagination.total_count;
                    } else {
                        // Fallback for old response format
                        this.users = data;
                    }
                    this.$log.debug('DATA', 'Loaded users:', this.users);
                    this.playersLoading = false;
                })
                .catch(error => {
                    this.$log.error('API', 'Error loading users:', error);
                    this.playersLoading = false;
                });
        },
        goToPage(newPage) {
            if (newPage >= 1 && newPage <= this.totalPages && newPage !== this.page) {
                this.page = newPage;
                this.loadUsers();
                // Update URL without page reload
                const url = new URL(window.location);
                url.pathname = `/admin/users/${newPage}`;
                window.history.pushState({}, '', url);
            }
        },
        sortUsers(column) {
            if (this.sortBy === column) {
                this.sortOrder = this.sortOrder === 'ASC' ? 'DESC' : 'ASC';
            } else {
                this.sortBy = column;
                this.sortOrder = 'ASC';
            }
            this.page = 1; // Reset to first page when sorting
            this.loadUsers();
        },
        filterByPrivilege(priv) {
            this.filterPriv = this.filterPriv === priv ? '' : priv;
            this.page = 1;
            this.loadUsers();
        },
        toggleSortOrder() {
            this.sortOrder = this.sortOrder === 'ASC' ? 'DESC' : 'ASC';
            this.page = 1;
            this.loadUsers();
        },
        clearSearch() {
            this.userquery = '';
            this.page = 1;
            this.loadUsers();
        },
        clearPrivilegeFilter() {
            this.filterPriv = '';
            this.page = 1;
            this.loadUsers();
        },
        resetSort() {
            this.sortBy = 'id';
            this.sortOrder = 'ASC';
            this.page = 1;
            this.loadUsers();
        },
        clearFilters() {
            this.userquery = '';
            this.filterPriv = '';
            this.filterCountry = '';
            this.sortBy = 'id';
            this.sortOrder = 'ASC';
            this.page = 1;
            this.loadUsers();
        },
        refreshUsers() {
            this.loadUsers();
        },
        getPrivilegeLabel(priv) {
            const labels = {
                '': 'All Users',
                'normal': 'Normal Users',
                'supporter': 'Supporters',
                'mod': 'Moderators',
                'admin': 'Administrators',
                'restricted': 'Restricted'
            };
            return labels[priv] || priv || 'All Users';
        },
        getSortLabel() {
            const sortLabels = {
                'id': 'ID',
                'name': 'Username',
                'creation_time': 'Join Date',
                'latest_activity': 'Last Active'
            };
            return `${sortLabels[this.sortBy] || this.sortBy} (${this.sortOrder})`;
        },
        getPrivilegeIcon(priv) {
            const icons = {
                '': 'fa-users',
                'normal': 'fa-user',
                'supporter': 'fa-heart',
                'mod': 'fa-shield-alt',
                'admin': 'fa-crown',
                'restricted': 'fa-ban'
            };
            return icons[priv] || 'fa-users';
        },
        getPrivilegeIconStyle(priv) {
            const colors = {
                '': '#6c7b7f',
                'normal': '#8fa8b2',
                'supporter': '#ff6b9d',
                'mod': '#48acff',
                'admin': '#ffd700',
                'restricted': '#ff4757'
            };
            return { color: colors[priv] || '#6c7b7f' };
        },
        editUser(userid) {
            editUserBus.$emit('showEditUserPanel', userid);
            this.$log.debug('EVENT', 'Edit User Window Trigger Emitted');
        },
    },
    computed: {
        paginationRange() {
            const range = [];
            const start = Math.max(1, this.page - 2);
            const end = Math.min(this.totalPages, this.page + 2);

            for (let i = start; i <= end; i++) {
                range.push(i);
            }
            return range;
        },
        hasActiveFilters() {
            return this.userquery ||
                   this.filterPriv ||
                   this.filterCountry ||
                   this.sortBy !== 'id' ||
                   this.sortOrder !== 'ASC';
        }
    }
});
var editUserBus = new Vue();
bootstrapVue('edit-user-panel',{
    el: "#editUserWindow",
    delimiters: ["<%", "%>"],
    data() {
        return {
            flags: window.flags,
            show: false,
            user: {},
            badges: {},
            load: false,
            playerLoading: false,
            postresponse: null,
            postresponsestatus: null,
            postresponsetimer: 0,
            module: 'Account', // added module data property
            subdropdown: null,
        }
    },
    created: function() {
        if (!this.$log) {
            this.$log = ColorfulLogger.child('Admin | Edit User Panel');
        }
        editUserBus.$on('showEditUserPanel', (userid) => {
            this.$log.debug('EVENT', 'Edit User Window Triggered')
            this.userid = userid;
            this.subdropdown = null;
            this.fetchSelectedUser(userid);
            this.getAllBadges();
            this.show = true;
        });
    },
    methods: {
        close: function() {
            this.show = false;
        },
        LoadUserEditor(module) {
            this.$log.debug('UI', `Loading ${module} editor...`); // placeholder print statement
            this.module = module;
        },
        showdropdown(subdropdown) {
            this.$log.debug('UI', `Showing ${subdropdown} dropdown...`); // placeholder print statement
            this.subdropdown = subdropdown;
        },
        fetchSelectedUser(userid) {
            const url = `/admin/user/${userid}`;
            fetch(url)
                
                .then(response => response.json())
                .then(data => {
                    this.user = null;
                    this.user = data;
                    this.$log.debug('DATA', 'User:', this.user);
                })
                .catch(error => {
                    this.$log.error('API', 'Error:', error);
                });
        },
        async postAction(url, formData) {
            const params = new URLSearchParams();
            for (const [key, value] of Object.entries(formData)) {
                params.append(key, value);
            }

            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: params
            });

            this.postresponsetimer = 5;
            this.postresponse = await response.json(); // Parse the response as JSON
            this.postresponsestatus = response.status; 
            const message = this.postresponse.message; // Get the message from the JSON response

            let timer = setInterval(() => {
                this.postresponsetimer--;
                if (this.postresponsetimer === 0) {
                    clearInterval(timer);
                    this.postresponse = null;
                }
            }, 1000);

            return message; // Return the message from the JSON response
        },
        getAllBadges() {
            const url = `/admin/badges?json=true`;
            fetch(url)
                .then(response => response.json())
                .then(data => {
                    this.badges = data;
                    this.$log.debug('DATA', 'Badges:', this.badges);
                })
                .catch(error => {
                    this.$log.error('API', 'Error:', error);
                });
            return this.badges;
        },
        toggleBadgeSelection(badgeid) {
            this.$log.debug('LOGIC', `Toggling badge ${badgeid}...`);
            this.$log.debug('DATA', 'User badges before toggling:', this.user.badges);
            if (this.user.badges.find(b => b.id === badgeid)) {
                this.user.badges.splice(this.user.badges.indexOf(badgeid), 1);
                this.postAction('/admin/action/removebadge', { user: this.user.id, badge: badgeid })
                    .then(status => {
                        if (status === 200) {
                            this.$log.debug('LOGIC', 'Badge removed:', badgeid);
                            this.$refs[badgeid][0].classList.toggle('selected');
                            this.fetchSelectedUser(this.user.id);
                        } else {
                            this.$log.error('LOGIC', 'Failed to remove badge:', badgeid);
                        }
                    })
                    .catch(error => {
                        this.$log.error('API', 'Error:', error);
                    });
            } else {
                this.user.badges.push(badgeid);
                this.postAction('/admin/action/addbadge', { user: this.user.id, badge: badgeid })
                    .then(status => {
                        if (status === 200) {
                            this.$log.debug('LOGIC', 'Badge added:', badgeid);
                            this.$refs[badgeid][0].classList.toggle('selected');
                            this.fetchSelectedUser(this.user.id);
                        } else {
                            this.$log.error('LOGIC', 'Failed to add badge:', badgeid);
                        }
                    })
                    .catch(error => {
                        this.$log.error('API', 'Error:', error);
                    });
            }
            
            this.$log.debug('DATA', 'User badges after toggling:', this.user.badges);
        }
    },
    computed: {
    },
    template: `#admin-edit-user-panel-template`
});



Vue.component('country-select', {
    props: ['value'],
    template: `
        <select v-model="selectedCountry">
            <option v-for="country in countries" :value="country.code">{{ country.name }}</option>
        </select>
    `,
    computed: {
        selectedCountry: {
            get() {
                return this.value;
            },
            set(value) {
                this.$emit('input', value);
            }
        }
    },
    data() {
        return {
            countries: [
                { name: 'United States', code: 'US' },
                { name: 'United Kingdom', code: 'GB' },
                { name: 'Afghanistan', code: 'AF' },
                { name: 'Albania', code: 'AL' },
                { name: 'Algeria', code: 'DZ' },
                { name: 'Andorra', code: 'AD' },
                { name: 'Angola', code: 'AO' },
                { name: 'Antigua and Barbuda', code: 'AG' },
                { name: 'Argentina', code: 'AR' },
                { name: 'Armenia', code: 'AM' },
                { name: 'Australia', code: 'AU' },
                { name: 'Austria', code: 'AT' },
                { name: 'Azerbaijan', code: 'AZ' },
                { name: 'Bahamas', code: 'BS' },
                { name: 'Bahrain', code: 'BH' },
                { name: 'Bangladesh', code: 'BD' },
                { name: 'Barbados', code: 'BB' },
                { name: 'Belarus', code: 'BY' },
                { name: 'Belgium', code: 'BE' },
                { name: 'Belize', code: 'BZ' },
                { name: 'Benin', code: 'BJ' },
                { name: 'Bermuda', code: 'BM' },
                { name: 'Bhutan', code: 'BT' },
                { name: 'Bolivia', code: 'BO' },
                { name: 'Bosnia and Herzegovina', code: 'BA' },
                { name: 'Botswana', code: 'BW' },
                { name: 'Brazil', code: 'BR' },
                { name: 'Brunei', code: 'BN' },
                { name: 'Bulgaria', code: 'BG' },
                { name: 'Burkina Faso', code: 'BF' },
                { name: 'Burundi', code: 'BI' },
                { name: 'Cambodia', code: 'KH' },
                { name: 'Cameroon', code: 'CM' },
                { name: 'Canada', code: 'CA' },
                { name: 'Cape Verde', code: 'CV' },
                { name: 'Central African Republic', code: 'CF' },
                { name: 'Chad', code: 'TD' },
                { name: 'Chile', code: 'CL' },
                { name: 'China', code: 'CN' },
                { name: 'Colombia', code: 'CO' },
                { name: 'Comoros', code: 'KM' },
                { name: 'Congo', code: 'CG' },
                { name: 'Costa Rica', code: 'CR' },
                { name: 'Croatia', code: 'HR' },
                { name: 'Cuba', code: 'CU' },
                { name: 'Cyprus', code: 'CY' },
                { name: 'Czech Republic', code: 'CZ' },
                { name: 'Denmark', code: 'DK' },
                { name: 'Djibouti', code: 'DJ' },
                { name: 'Dominica', code: 'DM' },
                { name: 'Dominican Republic', code: 'DO' },
                { name: 'East Timor', code: 'TL' },
                { name: 'Ecuador', code: 'EC' },
                { name: 'Egypt', code: 'EG' },
                { name: 'El Salvador', code: 'SV' },
                { name: 'Equatorial Guinea', code: 'GQ' },
                { name: 'Eritrea', code: 'ER' },
                { name: 'Estonia', code: 'EE' },
                { name: 'Eswatini', code: 'SZ' },
                { name: 'Ethiopia', code: 'ET' },
                { name: 'Fiji', code: 'FJ' },
                { name: 'Finland', code: 'FI' },
                { name: 'France', code: 'FR' },
                { name: 'Gabon', code: 'GA' },
                { name: 'Gambia', code: 'GM' },
                { name: 'Georgia', code: 'GE' },
                { name: 'Germany', code: 'DE' },
                { name: 'Ghana', code: 'GH' },
                { name: 'Greece', code: 'GR' },
                { name: 'Grenada', code: 'GD' },
                { name: 'Guatemala', code: 'GT' },
                { name: 'Guinea', code: 'GN' },
                { name: 'Guinea-Bissau', code: 'GW' },
                { name: 'Guyana', code: 'GY' },
                { name: 'Haiti', code: 'HT' },
                { name: 'Honduras', code: 'HN' },
                { name: 'Hungary', code: 'HU' },
                { name: 'Iceland', code: 'IS' },
                { name: 'India', code: 'IN' },
                { name: 'Indonesia', code: 'ID' },
                { name: 'Iran', code: 'IR' },
                { name: 'Iraq', code: 'IQ' },
                { name: 'Ireland', code: 'IE' },
                { name: 'Israel', code: 'IL' },
                { name: 'Italy', code: 'IT' },
                { name: 'Jamaica', code: 'JM' },
                { name: 'Japan', code: 'JP' },
                { name: 'Jordan', code: 'JO' },
                { name: 'Kazakhstan', code: 'KZ' },
                { name: 'Kenya', code: 'KE' },
                { name: 'Kiribati', code: 'KI' },
                { name: 'Korea, North', code: 'KP' },
                { name: 'Korea, South', code: 'KR' },
                { name: 'Kosovo', code: 'XK' },
                { name: 'Kuwait', code: 'KW' },
                { name: 'Kyrgyzstan', code: 'KG' },
                { name: 'Laos', code: 'LA' },
                { name: 'Latvia', code: 'LV' },
                { name: 'Lebanon', code: 'LB' },
                { name: 'Lesotho', code: 'LS' },
                { name: 'Liberia', code: 'LR' },
                { name: 'Libya', code: 'LY' },
                { name: 'Liechtenstein', code: 'LI' },
                { name: 'Lithuania', code: 'LT' },
                { name: 'Luxembourg', code: 'LU' },
                { name: 'Madagascar', code: 'MG' },
                { name: 'Malawi', code: 'MW' },
                { name: 'Malaysia', code: 'MY' },
                { name: 'Maldives', code: 'MV' },
                { name: 'Mali', code: 'ML' },
                { name: 'Malta', code: 'MT' },
                { name: 'Marshall Islands', code: 'MH' },
                { name: 'Mauritania', code: 'MR' },
                { name: 'Mauritius', code: 'MU' },
                { name: 'Mexico', code: 'MX' },
                { name: 'Micronesia', code: 'FM' },
                { name: 'Moldova', code: 'MD' },
                { name: 'Monaco', code: 'MC' },
                { name: 'Mongolia', code: 'MN' },
                { name: 'Montenegro', code: 'ME' },
                { name: 'Morocco', code: 'MA' },
                { name: 'Mozambique', code: 'MZ' },
                { name: 'Myanmar', code: 'MM' },
                { name: 'Namibia', code: 'NA' },
                { name: 'Nauru', code: 'NR' },
                { name: 'Nepal', code: 'NP' },
                { name: 'Netherlands', code: 'NL' },
                { name: 'New Zealand', code: 'NZ' },
                { name: 'Nicaragua', code: 'NI' },
                { name: 'Niger', code: 'NE' },
                { name: 'Nigeria', code: 'NG' },
                { name: 'North Macedonia', code: 'MK' },
                { name: 'Norway', code: 'NO' },
                { name: 'Oman', code: 'OM' },
                { name: 'Pakistan', code: 'PK' },
                { name: 'Palau', code: 'PW' },
                { name: 'Panama', code: 'PA' },
                { name: 'Papua New Guinea', code: 'PG' },
                { name: 'Paraguay', code: 'PY' },
                { name: 'Peru', code: 'PE' },
                { name: 'Philippines', code: 'PH' },
                { name: 'Poland', code: 'PL' },
                { name: 'Portugal', code: 'PT' },
                { name: 'Qatar', code: 'QA' },
                { name: 'Romania', code: 'RO' },
                { name: 'Russia', code: 'RU' },
                { name: 'Rwanda', code: 'RW' },
                { name: 'Saint Kitts and Nevis', code: 'KN' },
                { name: 'Saint Lucia', code: 'LC' },
                { name: 'Saint Vincent and the Grenadines', code: 'VC' },
                { name: 'Samoa', code: 'WS' },
                { name: 'San Marino', code: 'SM' },
                { name: 'Sao Tome and Principe', code: 'ST' },
                { name: 'Saudi Arabia', code: 'SA' },
                { name: 'Senegal', code: 'SN' },
                { name: 'Serbia', code: 'RS' },
                { name: 'Seychelles', code: 'SC' },
                { name: 'Sierra Leone', code: 'SL' },
                { name: 'Singapore', code: 'SG' },
                { name: 'Slovakia', code: 'SK' },
                { name: 'Slovenia', code: 'SI' },
                { name: 'Solomon Islands', code: 'SB' },
                { name: 'Somalia', code: 'SO' },
                { name: 'South Africa', code: 'ZA' },
                { name: 'South Sudan', code: 'SS' },
                { name: 'Spain', code: 'ES' },
                { name: 'Sri Lanka', code: 'LK' },
                { name: 'Sudan', code: 'SD' },
                { name: 'Suriname', code: 'SR' },
                { name: 'Sweden', code: 'SE' },
                { name: 'Switzerland', code: 'CH' },
                { name: 'Syria', code: 'SY' },
                { name: 'Taiwan', code: 'TW' },
                { name: 'Tajikistan', code: 'TJ' },
                { name: 'Tanzania', code: 'TZ' },
                { name: 'Thailand', code: 'TH' },
                { name: 'Togo', code: 'TG' },
                { name: 'Tonga', code: 'TO' },
                { name: 'Trinidad and Tobago', code: 'TT' },
                { name: 'Tunisia', code: 'TN' },
                { name: 'Turkey', code: 'TR' },
                { name: 'Turkmenistan', code: 'TM' },
                { name: 'Turks and Caicos Islands', code: 'TC' },
                { name: 'Tuvalu', code: 'TV' },
                { name: 'Uganda', code: 'UG' },
                { name: 'Ukraine', code: 'UA' },
                { name: 'United Arab Emirates', code: 'AE' },
                { name: 'Uruguay', code: 'UY' },
                { name: 'Uzbekistan', code: 'UZ' },
                { name: 'Vanuatu', code: 'VU' },
                { name: 'Vatican City', code: 'VA' },
                { name: 'Venezuela', code: 'VE' },
                { name: 'Vietnam', code: 'VN' },
                { name: 'Yemen', code: 'YE' },
                { name: 'Zambia', code: 'ZM' },
                { name: 'Zimbabwe', code: 'ZW' }
            ]
        };
    },
});