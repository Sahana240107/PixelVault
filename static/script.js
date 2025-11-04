const pageHome = document.getElementById('page-home');
const pageEncrypt = document.getElementById('page-encrypt');
const pageDecrypt = document.getElementById('page-decrypt');
const statusPill = document.getElementById('status');

function showPage(name) {
  pageHome.style.display = name === 'home' ? 'block' : 'none';
  pageEncrypt.style.display = name === 'encrypt' ? 'block' : 'none';
  pageDecrypt.style.display = name === 'decrypt' ? 'block' : 'none';
  statusPill.textContent = name[0].toUpperCase() + name.slice(1);
}

document.getElementById('go-encrypt').onclick = () => showPage('encrypt');
document.getElementById('go-decrypt').onclick = () => showPage('decrypt');
document.getElementById('quick-encrypt').onclick = () => showPage('encrypt');
document.getElementById('quick-decrypt').onclick = () => showPage('decrypt');

const toast = document.getElementById('toast');
let toastTimer = null;
function showToast(msg, ms = 3000) {
  toast.textContent = msg;
  toast.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.style.display = 'none', ms);
}

// Encrypt handling
const coverFile = document.getElementById('cover-file');
const coverPreview = document.getElementById('cover-preview');
const coverImg = document.getElementById('cover-img');
const encryptOutput = document.getElementById('encrypt-output');

coverFile.addEventListener('change', () => {
  const f = coverFile.files[0];
  if (!f) return;
  const url = URL.createObjectURL(f);
  coverImg.src = url;
  coverPreview.style.display = 'flex';
});

document.getElementById('form-encrypt').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = coverFile.files[0];
  const message = document.getElementById('message').value;
  const password = document.getElementById('password').value;
  if (!f || !message || !password) {
    showToast('Please fill all fields');
    return;
  }

  showToast('Encrypting...');
  const fd = new FormData();
  fd.append('image', f);
  fd.append('message', message);
  fd.append('password', password);

  try {
    const res = await fetch('/encrypt', { method: 'POST', body: fd });
    if (!res.ok) throw new Error(await res.text());
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'stego.png';
    a.click();
    showToast('Download started: stego.png');
  } catch (err) {
    showToast('Error: ' + err.message, 5000);
  }
});

document.getElementById('reset-encrypt').onclick = () => {
  document.getElementById('form-encrypt').reset();
  coverPreview.style.display = 'none';
  encryptOutput.style.display = 'none';
};

// Decrypt handling
const stegoFile = document.getElementById('stego-file');
const stegoPreview = document.getElementById('stego-preview');
const stegoImg = document.getElementById('stego-img');
const decryptOutput = document.getElementById('decrypt-output');

stegoFile.addEventListener('change', () => {
  const f = stegoFile.files[0];
  if (!f) return;
  stegoImg.src = URL.createObjectURL(f);
  stegoPreview.style.display = 'flex';
});

document.getElementById('form-decrypt').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = stegoFile.files[0];
  const password = document.getElementById('dec-password').value;
  if (!f || !password) {
    showToast('Please fill both fields');
    return;
  }

  showToast('Decrypting...');
  const fd = new FormData();
  fd.append('image', f);
  fd.append('password', password);

  try {
    const res = await fetch('/decrypt', { method: 'POST', body: fd });
const data = await res.json();

if (!res.ok || data.error) {
  showToast(data.error || 'Decryption failed', 5000);
  decryptOutput.style.display = 'block';
  decryptOutput.innerHTML = `<span style="color:#ff6b6b"><strong>${data.error || 'Decryption failed'}</strong></span>`;
  return;
}

decryptOutput.style.display = 'block';
decryptOutput.innerHTML = `<strong>Hidden message:</strong><pre>${data.message}</pre>`;
showToast('Decryption success');

  } catch (err) {
    showToast('Error: ' + err.message, 5000);
  }
});

document.getElementById('reset-decrypt').onclick = () => {
  document.getElementById('form-decrypt').reset();
  stegoPreview.style.display = 'none';
  decryptOutput.style.display = 'none';
};

showPage('home');
