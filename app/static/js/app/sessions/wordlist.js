var CJ_SessionsWordlists = {
    init: function() {
        this.bindFile();
    },

    bindFile: function() {
        $('.custom-file-input').on('change', function() {
            CJ_SessionsWordlists.setFilename(this);
            return true;
        });
    },

    setFilename: function(input) {
        filename = $(input).val().split('\\').pop();
        console.log('filename', filename)
        $(input).parent().children('.custom-file-label').text(filename)
    },
};
