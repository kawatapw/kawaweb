new Vue({
    el: "#app",
    delimiters: ["<%", "%>"],
    data() {
        return {
            flags: window.flags,
            changelogs: [],
            logs: [],
            type: 'frontend',
            category: 'all',
            load: true,
        };
    },
    created() {
        this.$log.info('LIFECYCLE', "Loading Changelog Page");
        this.changelogs = window.changelogs;
        this.$log.debug('DATA', "Changelogs:", this.changelogs);

        // Parse the current URL to set the initial type and category
        const pathSegments = window.location.pathname.split('/').filter(Boolean);
        if (pathSegments.length >= 2) {
            this.type = pathSegments[1]; // Assuming the URL structure is /changelog/{type}/{category}
            this.category = pathSegments.length > 2 ? pathSegments[2] : 'all';
        }

        this.LoadChangelogs(this.changelogs, this.type, this.category);
    },
    methods: {
        LoadData(changelogs, type, category) {
            this.$set(this, 'changelogs', changelogs);
            this.$set(this, 'type', type);
            this.$set(this, 'category', category);
        },
        LoadChangelogs(changelogs, type, category) {
            if (window.event)
                window.event.preventDefault();

            window.history.replaceState('', document.title, `/changelog/${type}/${category}`);

            // Map type from string to integer
            const typeMap = {
                'frontend': 0,
                'backend': 1,
                'client': 2
            };
            const typeInt = typeMap[type];
            // Filter changelogs based on type and category
            const filteredChangelogs = changelogs.filter(changelog => {
                return (changelog.type === typeInt) && (category === 'all' || changelog.category === category);
            });

            // Sort filtered changelogs by time column in descending order
            filteredChangelogs.sort((a, b) => b.time - a.time);

            this.$set(this, 'logs', filteredChangelogs);
            this.$set(this, 'type', type);
            this.$set(this, 'category', category);
            this.$set(this, 'load', false);
        },
        addCommas(nStr) {
            nStr += '';
            var x = nStr.split('.');
            var x1 = x[0];
            var x2 = x.length > 1 ? '.' + x[1] : '';
            var rgx = /(\d+)(\d{3})/;
            while (rgx.test(x1)) {
                x1 = x1.replace(rgx, '$1' + ',' + '$2');
            }
            return x1 + x2;
        },
    },
});