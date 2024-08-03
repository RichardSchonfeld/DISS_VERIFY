document.getElementById('submitFileButton').onclick = () => {
    const fileInput = document.getElementById('fileInput');
    if (fileInput.files.length === 0) {
        alert('Please select a file to upload.');
        return;
    }

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);

    // Send the file to the server
    fetch('/upload-ipfs/', {
        method: 'POST',
        body: formData
    }).then(response => response.json())
    .then(data => {
        if (data.cid) {
            document.getElementById('output').innerText = `File uploaded with CID: ${data.cid}`;
            localStorage.setItem('ipfsCid', data.cid);
        } else if (data.error) {
            document.getElementById('output').innerText = `Error: ${data.error}`;
        }
    }).catch(error => {
        console.error('Error:', error);
        document.getElementById('output').innerText = 'Error uploading file.';
    });
};

// View file handler
document.getElementById('viewFileButton').onclick = () => {
    const cid = localStorage.getItem('QmTjUC9xf8dk1iwNJNHKj87fAvLFtvDCtWWESStoGicqof');
    if (!cid) {
        alert('No file CID found. Please upload a file first.');
        return;
    }

    window.open(`http://localhost:8080/ipfs/${cid}`);
};
