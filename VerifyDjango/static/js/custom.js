$(document).ready(function() {
    $('#createClaimForm').on('submit', function(event) {
        event.preventDefault();

        let formData = {
            username: $('#username').val(),
            authority: $('#authority').val(),
            year_of_graduation: $('#yearOfGraduation').val(),
            student_number: $('#studentNumber').val(),
            full_name: $('#fullName').val(),
        };

        $.ajax({
            url: 'http://localhost:8000/api/create_claim/',
            type: 'POST',
            data: JSON.stringify(formData),
            contentType: 'application/json',
            success: function(response) {
                alert('Claim created successfully! Transaction Hash: ' + response.tx_hash);
                // Optionally, refresh the list of claims or update the UI
            },
            error: function(error) {
                console.error('Error creating claim:', error);
                alert('Failed to create claim');
            }
        });
    });
});
