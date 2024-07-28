$(document).ready(function() {
    $.ajax({
        url: 'http://localhost:8000/api/list-claims/',
        method: 'GET',
        success: function(data) {
            var claimsList = $('#claims-list');
            data.forEach(function(claim) {
                var listItem = '<li>' +
                    claim.full_name + ' - ' +
                    claim.year_of_graduation + ' - ' +
                    claim.student_number + ' - ' +
                    claim.ipfs_hash + ' - ' +
                    (claim.signed ? 'Signed' : 'Not Signed') +
                    '</li>';
                claimsList.append(listItem);
            });
        },
        error: function(error) {
            console.error('There was an error fetching the claims!', error);
        }
    });
});
