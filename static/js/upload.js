const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('file');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const uploadBtn = document.querySelector('.upload-btn');
const uploadContent = document.querySelector('.upload-content');

document.querySelector('.choose-file-btn').addEventListener('click', function () {
    fileInput.click();
});

document.querySelector('.clear-file-btn').addEventListener('click', clearFile);

uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('drag-over');
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('drag-over');
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        fileInput.files = files;
        showFileInfo(files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        showFileInfo(e.target.files[0]);
    }
});

function showFileInfo(file) {
    fileName.textContent = file.name;
    uploadContent.classList.add('d-none');
    fileInfo.classList.remove('d-none');
    uploadBtn.disabled = false;
}

function clearFile() {
    fileInput.value = '';
    uploadContent.classList.remove('d-none');
    fileInfo.classList.add('d-none');
    uploadBtn.disabled = true;
}
