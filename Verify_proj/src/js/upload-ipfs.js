import { Helia } from '@helia/core';

// Initialize Helia instance
const helia = new Helia();

// Example function to add content
async function addFile(content) {
  const cid = await helia.add(content);
  console.log(`File added with CID: ${cid}`);
  return cid;
}

// Example usage for upload button
document.getElementById('uploadButton').onclick = async () => {
  const fileInput = document.getElementById('fileInput');
  if (fileInput.files.length === 0) {
    alert('Please select a file to upload.');
    return;
  }

  const file = fileInput.files[0];
  try {
    const cid = await addFile(file);
    document.getElementById('output').innerText = `File uploaded successfully: ${cid}`;
    localStorage.setItem('ipfsCid', cid);
  } catch (error) {
    console.error('Error uploading file:', error);
  }
};

// Example usage for view button
document.getElementById('viewButton').onclick = async () => {
  const cid = localStorage.getItem('ipfsCid');
  if (!cid) {
    alert('No file uploaded yet.');
    return;
  }

  try {
    const file = await helia.cat(cid);
    document.getElementById('output').innerText = `File content: ${file.toString()}`;
  } catch (error) {
    console.error('Error retrieving file:', error);
  }
};
