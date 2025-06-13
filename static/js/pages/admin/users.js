new Vue({
    el: "#users",
    delimiters: ["<%", "%>"],
    data() {
        return {
            flags: window.flags,
            users: {},
            page: 1,
            userquery: '', // changed from 'search' to 'userquery'
            load: false,
            playersLoading: false,
            searchTimeout: null,
        }
    },
    created() {
        this.$log.debug('Users.js User Page Created');
        this.handleUserInput(userquery);
    },
    methods: {
        handleUserInput() {
            clearTimeout(this.searchTimeout);
            if (this.userquery.length > 0)
                this.searchTimeout = setTimeout(() => {
                    const queryUsers = this.userquery;
                    const url = `/admin/users/${this.page}?update=true&search=${queryUsers}`;
                    fetch(url)
                        .then(response => response.json())
                        .then(data => {
                            this.users = data;
                            this.$log.debug('users:', this.users);
                        })
                        .catch(error => {
                            this.$log.error('Error:', error);
                        });
                }, 500);
            else {
                const queryUsers = this.userquery;
                const url = `/admin/users/${this.page}?update=true&search=${queryUsers}`;
                fetch(url)
                    .then(response => response.json())
                    .then(data => {
                        this.users = data;
                        this.$log.debug('users:', this.users);
                    })
                    .catch(error => {
                        this.$log.error('Error:', error);
                    });
                
            }
        },
        editUser(userid) {
            editUserBus.$emit('showEditUserPanel', userid);
            this.$log.debug('Edit User Window Trigger Emitted');
        },
    },
    computed: {
    }
});
var editUserBus = new Vue();
new Vue({
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
    methods: {
        close: function() {
            this.show = false;
        },
        LoadUserEditor(module) {
            this.$log.debug(`Loading ${module} editor...`); // placeholder print statement
            this.module = module;
        },
        showdropdown(subdropdown) {
            this.$log.debug(`Showing ${subdropdown} dropdown...`); // placeholder print statement
            this.subdropdown = subdropdown;
        },
        fetchSelectedUser(userid) {
            const url = `/admin/user/${userid}`;
            fetch(url)
                
                .then(response => response.json())
                .then(data => {
                    this.user = null;
                    this.user = data;
                    this.$log.debug('User:', this.user);
                })
                .catch(error => {
                    this.$log.error('Error:', error);
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
                    this.$log.debug('Badges:', this.badges);
                })
                .catch(error => {
                    this.$log.error('Error:', error);
                });
            return this.badges;
        },
        toggleBadgeSelection(badgeid) {
            this.$log.debug(`Toggling badge ${badgeid}...`);
            this.$log.debug('User badges before toggling:', this.user.badges);
            if (this.user.badges.find(b => b.id === badgeid)) {
                this.user.badges.splice(this.user.badges.indexOf(badgeid), 1);
                this.postAction('/admin/action/removebadge', { targets: this.user.id, badge: badgeid })
                    .then(status => {
                        if (status === 200) {
                            this.$log.debug('Badge removed:', badgeid);
                            this.$refs[badgeid][0].classList.toggle('selected');
                            this.fetchSelectedUser(this.user.id);
                        } else {
                            this.$log.error('Failed to remove badge:', badgeid);
                        }
                    })
                    .catch(error => {
                        this.$log.error('Error:', error);
                    });
            } else {
                this.user.badges.push(badgeid);
                this.postAction('/admin/action/addbadge', { targets: this.user.id, badge: badgeid })
                    .then(status => {
                        if (status === 200) {
                            this.$log.debug('Badge added:', badgeid);
                            this.$refs[badgeid][0].classList.toggle('selected');
                            this.fetchSelectedUser(this.user.id);
                        } else {
                            this.$log.error('Failed to add badge:', badgeid);
                        }
                    })
                    .catch(error => {
                        this.$log.error('Error:', error);
                    });
            }
            
            this.$log.debug('User badges after toggling:', this.user.badges);
        }
    },
    created: function() {
        editUserBus.$on('showEditUserPanel', (userid) => {
            this.$log.debug('Edit User Window Triggered')
            this.userid = userid;
            this.subdropdown = null;
            this.fetchSelectedUser(userid);
            this.getAllBadges();
            this.show = true;
        });
    },
    computed: {
    },
    template: `
    <div id="editUserWindow" class="modal" v-bind:class="{ 'is-active': show }">
        <div class="modal-background" @click="close"></div>
        <div id="editUserWindow" class="modal-content" v-if="show">
            <div id="editUser" class="box">
                <div id="editUser" class="user-banner" >
                    <div id="editUserBanner" class="user-banner-background" :style="'background-image: url(/banners/' + userid + ')'" alt="User Banner">
                        <div class="info-block">
                            <h1 class="title">
                                <p class="ranks">
                                    <img :src="'/static/images/flags/' + user.country.toUpperCase() + '.png'" class="user-flag">
                                    <span class="bgf"><% user.name %></span>
                                </p>
                            </h1>
                        </div>
                    </div>
                    <div class="user-flex">
                        <div class="user-avatar-area">
                            <img :src="'https://a.' + domain + '/' + userid" alt="avatar" class="rounded-avatar user-avatar"
                                onError="this.src='/static/images/avatar_notwork.png';">
                        </div>
                        <div class="bar-selection mode-selects">
                            <div id="editUser" class="select-left">
                                <a class="simple-banner-switch" v-bind:class="{ 'active': module === 'Account' }"
                                @click="LoadUserEditor('Account', module)">
                                    <i class="fas fa-user"></i><span class="modetext"> Account </span>
                                </a>
                                <a class="simple-banner-switch" v-bind:class="{ 'active': module === 'Badges' }"
                                @click="LoadUserEditor('Badges', module)">
                                    <i class="fas fa-shield"></i><span class="modetext"> Badges </span>
                                </a>
                                <a class="simple-banner-switch" v-bind:class="{ 'active': module === 'Privileges' }"
                                @click="LoadUserEditor('Privileges', module)">
                                    <i class="fas fa-lock"></i><span class="modetext"> Privileges </span>
                                </a>
                                <a class="simple-banner-switch" v-bind:class="{ 'active': module === 'Logs' }"
                                @click="LoadUserEditor('Logs', module)">
                                    <i class="fas fa-book"></i><span class="modetext"> Logs </span>
                                </a>
                            </div>
                        </div>
                        <div class="bar-selection badge-selects">
                            <div v-if="user.badges.length != 0" class="select-left badge-block">
                                <badge v-for="badge in user.badges" :badge="badge"></badge>
                            </div>
                            <div v-else class="select-left">
                                <div class="badge-block">
                                    <span>
                                        This user has no badges.
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div id="editUser" class="main-block">
                    <div class="alert" v-if="postresponse" :style="'background-color: var(--alert-' + postresponsestatus + ');'">
                        <div class="alert-content">
                            <p><% postresponse.message %></p>
                        </div>
                    </div>
                    <div class="content" v-if="module === 'Account'">
                        <div class="column">
                            <span class="title is-4 is-centered">Quick Actions</span>
                            <div id="quickActions" class="level is-centered">
                                <div class="level-item">
                                    <div class="dropdown is-hoverable">
                                        <div class="dropdown-trigger">
                                            <button class="button is-danger" aria-haspopup="true" aria-controls="wipe-dropdown-menu">
                                                Wipe
                                            </button>
                                        </div>
                                        <div class="dropdown-menu" id="wipe-dropdown-menu" role="menu">
                                            <div class="dropdown-content">
                                                <a class="dropdown-item" @click="postAction('/admin/action/wipe', { targets: [user.id], reason: 'Auto mod' })">
                                                    Auto mod
                                                </a>
                                                <a class="dropdown-item" @click="postAction('/admin/action/wipe', { targets: [user.id], reason: 'FL abuse' })">
                                                    FL abuse
                                                </a>
                                                <a class="dropdown-item" @click="postAction('/admin/action/wipe', { targets: [user.id], reason: 'Requested Wipe' })">
                                                    Requested Wipe
                                                </a>
                                                <a class="dropdown-item" @click="postAction('/admin/action/wipe', { targets: [user.id], reason: 'Overcheating' })">
                                                    Overcheating
                                                </a>
                                                <div class="dropdown-divider"></div>
                                                <a class="dropdown-item" @click="showdropdown('customwipe', subdropdown)">
                                                    Custom Reason
                                                </a>
                                                <span v-if="subdropdown === 'customwipe'">
                                                    <div class="field">
                                                        <label class="label">Custom Wipe Reason</label>
                                                        <div class="control userspanel">
                                                            <input class="input" type="reason" id="wipe-reason-input">
                                                        </div>
                                                    </div>
                                                    <div class="field">
                                                        <div class="control userspanel">
                                                            <button class="button is-success" @click="postAction('/admin/action/wipe', { targets: [user.id], reason: document.getElementById('wipe-reason-input').value })">
                                                                Wipe
                                                            </button>
                                                        </div>
                                                    </div>
                                                </span>
                                                <div class="dropdown-divider"></div>
                                                <a class="dropdown-item" @click="showdropdown('removescore', subdropdown)">
                                                    Score Removal
                                                </a>
                                                <span v-if="subdropdown === 'removescore'">
                                                    <div class="field">
                                                        <label class="label">Score Removal Reason</label>
                                                        <div class="control userspanel">
                                                            <input class="input" type="reason" id="wipescore-reason-input">
                                                        </div>
                                                    </div>
                                                    <div class="field">
                                                        <label class="label">Score ID</label>
                                                        <div class="control userspanel">
                                                            <input class="input" type="id" id="wipescore-id-input">
                                                        </div>
                                                    </div>
                                                    <div class="field">
                                                        <div class="control userspanel">
                                                            <button class="button is-success" @click="postAction('/admin/action/removescore', { targets: [user.id], reason: document.getElementById('wipescore-reason-input').value, score: document.getElementById('wipescore-id-input').value })">
                                                                Remove Score
                                                            </button>
                                                        </div>
                                                    </div>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="level-item">
                                    <div class="dropdown is-hoverable">
                                        <div class="dropdown-trigger">
                                            <button class="button is-warning" aria-haspopup="true" aria-controls="silence-dropdown-menu">
                                                Restrict
                                            </button>
                                        </div>
                                        <div class="dropdown-menu" id="wipe-dropdown-menu" role="menu">
                                            <div class="dropdown-content">
                                                <a class="dropdown-item" @click="postAction('/admin/action/restrict', { targets: [user.id], reason: 'Repeated Offenses' })">
                                                    Repeated Offenses
                                                </a>
                                                <a class="dropdown-item" @click="postAction('/admin/action/restrict', { targets: [user.id], reason: '3rd Wipe' })">
                                                    3rd Wipe
                                                </a>
                                                <div class="dropdown-divider"></div>
                                                <a class="dropdown-item" @click="showdropdown('customrestrict', subdropdown)">
                                                    Custom Reason
                                                </a>
                                                <span v-if="subdropdown === 'customrestrict'">
                                                    <div class="field">
                                                        <label class="label">Custom Restrict Reason</label>
                                                        <div class="control userspanel">
                                                            <input class="input" type="reason" id="restrict-reason-input">
                                                        </div>
                                                    </div>
                                                    <div class="field">
                                                        <div class="control userspanel">
                                                            <button class="button is-success" @click="postAction('/admin/action/restrict', { targets: [user.id], reason: document.getElementById('restrict-reason-input').value })">
                                                                Restrict
                                                            </button>
                                                        </div>
                                                    </div>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="level-item">
                                    <button class="button is-success" @click="postAction('/admin/action/unrestrict', { targets: [user.id] })">Unrestrict</button>
                                </div>
                                <div class="level-item">
                                    <div class="dropdown is-hoverable">
                                        <div class="dropdown-trigger">
                                            <button class="button is-info" aria-haspopup="true" aria-controls="silence-dropdown-menu">
                                                Silence
                                            </button>
                                        </div>
                                        <div class="dropdown-menu" id="wipe-dropdown-menu" role="menu">
                                            <div class="dropdown-content">
                                                <a class="dropdown-item" @click="postAction('/admin/action/silence', { targets: [user.id], duration: '2', reason: 'Spam' })">
                                                    Spam
                                                </a>
                                                <a class="dropdown-item" @click="postAction('/admin/action/silence', { targets: [user.id], duration: '6', reason: 'Consistent usage of inappropriate language' })">
                                                    Consistent usage of inappropriate language
                                                </a>
                                                <div class="dropdown-divider"></div>
                                                <a class="dropdown-item" @click="showdropdown('customsilence', subdropdown)">
                                                    Custom Reason
                                                </a>
                                                <span v-if="subdropdown === 'customsilence'">
                                                    <div class="field">
                                                        <label class="label">Custom Silence Reason</label>
                                                        <div class="control userspanel">
                                                            <input class="input" type="reason" id="silence-reason-input">
                                                        </div>
                                                    </div>
                                                    <div class="field">
                                                        <label class="label">Silence Duration (in hours)</label>
                                                        <div class="control userspanel">
                                                            <input class="input" type="number" id="silence-duration-input">
                                                        </div>
                                                    </div>
                                                    <div class="field">
                                                        <div class="control userspanel">
                                                            <button class="button is-success" @click="postAction('/admin/action/silence', { targets: [user.id], duration: document.getElementById('silence-duration-input').value, reason: document.getElementById('silence-reason-input').value })">
                                                                Silence
                                                            </button>
                                                        </div>
                                                    </div>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="level-item">
                                    <button class="button is-primary" @click="postAction('/admin/action/unsilence', { targets: [user.id] })">Unsilence</button>
                                </div>
                                <div class="level-item">
                                    <div class="dropdown is-hoverable">
                                        <div class="dropdown-trigger">
                                            <button class="button is-primary" aria-haspopup="true" aria-controls="change-password-dropdown-menu">
                                                Change Password
                                            </button>
                                        </div>
                                        <div class="dropdown-menu" id="change-password-dropdown-menu" role="menu">
                                            <div class="dropdown-content">
                                                <div class="field">
                                                    <label class="label">New Password</label>
                                                    <div class="control userspanel">
                                                        <input class="input" type="password" id="new-password-input">
                                                    </div>
                                                </div>
                                                <div class="field">
                                                    <div class="control userspanel">
                                                        <button class="button is-success" @click="postAction('/admin/action/changepassword', { targets: [user.id], password: document.getElementById('new-password-input').value })">
                                                            Save
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <form @submit.prevent="postAction('/admin/action/editaccount', {
                            targets: user.id,
                            username: user.name,
                            email: user.email,
                            country: user.country,
                            userpage_content: user.userpage_content
                        })">
                            <div class="field">
                                <label class="label">User ID</label>
                                <div class="control userspanel">
                                    <input class="input" type="text" :value="user.id" readonly>
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">Username</label>
                                <div class="control userspanel">
                                    <input class="input" type="text" name="username" v-model="user.name">
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">Email</label>
                                <div class="control userspanel">
                                    <input class="input" type="email" name="email" v-model="user.email">
                                </div>
                            </div>
                            <div class="field" v-if="user.country">
                                <label class="label">Country</label>
                                <div class="control userspanel">
                                    <div class="select is-fullwidth">
                                        <country-select v-model="user.country"></country-select>
                                    </div>
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">User Page Content</label>
                                <div class="control userspanel">
                                    <textarea id="userpage_content" class="input" name="userpage_content" v-model="user.userpage_content"></textarea>
                                </div>
                            </div>
                            <div class="field is-grouped">
                                <div class="control userspanel">
                                    <button class="button is-primary" type="submit">Save</button>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div class="content" v-if="module === 'Badges'">
                        Note: You must leave and re-enter this page to undo any badge changes. Will be fixed eventually.
                        <div id="badges" class="columns is-multiline">
                            <div v-for="(badge, index) in badges" :key="badge.id" class="column is-half">
                                <div id="badge" class="card" :class="{ 'selected': user.badges.find(b => b.id === badge.id) }" :ref="badge.id" @click="toggleBadgeSelection(badge.id)">
                                    <div id="badge" class="card-image">
                                        <i :class="'badge-icon ' + badge.styles.icon" :style="'color: hsl('+ badge.styles.color +', 80%, 80%);'"></i>
                                    </div>
                                    <div id="badge" class="card-content">
                                        <h3 class="title" :style="'color: hsl('+ badge.styles.color +', 80%, 80%);'"><% badge.name %></h3>
                                        <p><% badge.description %></p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="content" v-if="module === 'Privileges'">
                        <p>Privileges editor placeholder</p> <!-- placeholder print statement -->
                    </div>
                    <div id="logs" class="content" v-if="module === 'Logs'">
                        <h5 class="title">Admin Logs</h5>
                        <div id="logs" class="columns is-multiline">
                            <div v-for="(log, index) in user.logs.admin_logs" :key="log.id" class="column is-half">
                                <div id="log" class="card">
                                    <div id="log" class="card-content">
                                        <div class="Sender">
                                            <div class="SenderAvatar">
                                                <img :src="'https://a.' + domain + '/' + log.mod.id" alt="avatar" class="rounded-avatar">
                                            </div>
                                            <div class="SenderInfo">
                                                <h3 class="from">Action taken by:</h3>
                                                <h4>
                                                    <img :src="'/static/images/flags/' + log.mod.country.toUpperCase() + '.png'" class="user-flag">
                                                    <a :href="'/u/' + log.mod.id"><% log.mod.name %></a>
                                                </h4>
                                                <h5>On: <% log.time %></h5>
                                            </div>
                                        </div>
                                        <div class="Action">
                                            <h3 class="title">Action: <% log.action %></h3>
                                            <h4>Reason: <% log.reason %></p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <h5 class="title">Client Hashes</h5>
                        <div id="hashes" class="columns is-multiline">
                            <div v-for="(hash, index) in user.logs.hashes" :key="index" class="column is-half">
                                <div id="hash" class="card">
                                    <div id="hash" class="card-content">
                                        <h3 class="title">Client Hashes:</h3>
                                        <p class="detail">Occurrences: <% hash.occurrences %></p>
                                        <p class="detail">Last Occurance: <% hash.latest_time %></p>
                                        <p class="detail">Adapters Hash: <% hash.adapters %></p>
                                        <p class="detail">Disk Serial: <% hash.disk_serial %></p>
                                        <p class="detail">OSU Path Hash: <% hash.osupath %></p>
                                        <p class="detail">Uninstall ID: <% hash.uninstall_id %></p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
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