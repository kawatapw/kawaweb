new Vue({
    el: '#home-hero',
    delimiters: ['<%', '%>'],
    data() {
        return {
            online_users: 0,
        }
    },
    created() {
        var vm = this;
        vm.GetOnlineUsers()
    },
    methods: {
        GetOnlineUsers() {
            var vm = this;
            // For local development, use the same domain with /api prefix
            const apiUrl = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
                ? `${window.location.protocol}//${window.location.host}/api/v1/get_player_count`
                : `${window.location.protocol}//api.${domain}/v1/get_player_count`;
            vm.$axios.get(apiUrl)
                .then(function (response) {
                    vm.online_users = response.data.count || 0;
                });
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
        }
    },
    computed: {
    }
});