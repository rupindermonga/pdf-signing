// ─── Constants ───
const VERIFY_URL = 'https://rupindermonga.github.io/pdf-signing/';

// ─── State ───
const state = {
  pdfFile: null,
  pdfBytes: null,
  pdfDoc: null,
  currentPage: 1,
  totalPages: 1,
  zoom: 1.0,
  sigPlaced: false,
  // Security
  documentId: '',
  originalHash: '',
  clientIp: '',
  geoCoords: null,
  browserInfo: '',
};

// ─── Elements ───
const $ = (sel) => document.querySelector(sel);
const uploadSection  = $('#upload-section');
const detailsSection = $('#details-section');
const placementSection = $('#placement-section');

const dropZone   = $('#drop-zone');
const pdfInput   = $('#pdf-input');
const fileInfo   = $('#file-info');
const fileName   = $('#file-name');
const removeFile = $('#remove-file');

const signerName     = $('#signer-name');
const signReason     = $('#sign-reason');
const signReasonCustom = $('#sign-reason-custom');
const signLocation   = $('#sign-location');
const locationStatus = $('#location-status');
const refreshLocation = $('#refresh-location');
const signDate       = $('#sign-date');

const sigCanvas     = $('#sig-canvas');
const sigCtx        = sigCanvas.getContext('2d');
const clearCanvas   = $('#clear-canvas');
const penColor      = $('#pen-color');
const penSize       = $('#pen-size');
const typedSig      = $('#typed-sig');

const proceedBtn    = $('#proceed-placement');
const prevPage      = $('#prev-page');
const nextPage      = $('#next-page');
const pageInfo      = $('#page-info');
const zoomIn        = $('#zoom-in');
const zoomOut       = $('#zoom-out');
const zoomLevel     = $('#zoom-level');

const pdfContainer = $('#pdf-container');
const pdfCanvas    = $('#pdf-canvas');
const sigOverlay   = $('#sig-overlay');

const backBtn      = $('#back-to-details');
const downloadBtn  = $('#download-signed');
const loading      = $('#loading');

// ─── Helpers ───
function generateUUID() {
  return 'DS-' + 'xxxx-xxxx-xxxx'.replace(/x/g, () =>
    Math.floor(Math.random() * 16).toString(16)
  ).toUpperCase();
}

async function computeSHA256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function formatDate(date) {
  const d = date || new Date();
  const day = String(d.getDate()).padStart(2, '0');
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const mon = months[d.getMonth()];
  const year = d.getFullYear();
  let hours = d.getHours();
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12 || 12;
  const mins = String(d.getMinutes()).padStart(2, '0');
  return `${day}-${mon}-${year} (${String(hours).padStart(2,'0')}:${mins} ${ampm})`;
}

function formatFullTimestamp() {
  return new Date().toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
}

function getBrowserInfo() {
  const ua = navigator.userAgent;
  let browser = 'Unknown';
  if (ua.includes('Firefox/')) browser = 'Firefox';
  else if (ua.includes('Edg/')) browser = 'Edge';
  else if (ua.includes('Chrome/')) browser = 'Chrome';
  else if (ua.includes('Safari/')) browser = 'Safari';
  let os = 'Unknown';
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac OS')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
  return `${browser} on ${os}`;
}

function updateDateTime() {
  const now = formatDate();
  signDate.value = now;
  $('#preview-date').textContent = now;
}

function showSection(section) {
  [uploadSection, detailsSection, placementSection].forEach(s => s.classList.add('hidden'));
  section.classList.remove('hidden');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Fetch client public IP ───
async function fetchClientIp() {
  // Try external service first for real public IP (works even on localhost)
  try {
    const resp = await fetch('https://api.ipify.org?format=json');
    const data = await resp.json();
    if (data.ip) { state.clientIp = data.ip; return; }
  } catch { /* fall through */ }
  // Fallback to server-reported IP
  try {
    const resp = await fetch('/api/ip');
    const data = await resp.json();
    state.clientIp = data.ip || 'Unknown';
  } catch { state.clientIp = 'Unknown'; }
}

// ─── Auto-detect Location ───
function detectLocation() {
  locationStatus.textContent = 'detecting...';
  locationStatus.className = 'location-status detecting';
  signLocation.value = '';
  signLocation.placeholder = 'Detecting your location...';

  if (!navigator.geolocation) {
    locationStatus.textContent = '(not supported)';
    locationStatus.className = 'location-status error';
    signLocation.placeholder = 'Enter location manually';
    signLocation.removeAttribute('readonly');
    return;
  }

  navigator.geolocation.getCurrentPosition(
    async (position) => {
      const { latitude, longitude } = position.coords;
      state.geoCoords = { lat: latitude.toFixed(6), lon: longitude.toFixed(6) };
      try {
        const resp = await fetch(
          `https://nominatim.openstreetmap.org/reverse?lat=${latitude}&lon=${longitude}&format=json&zoom=10`,
          { headers: { 'Accept-Language': 'en' } }
        );
        const data = await resp.json();
        const addr = data.address || {};
        const city = addr.city || addr.town || addr.village || addr.county || '';
        const stateRegion = addr.state || '';
        const country = addr.country || '';
        const parts = [city, stateRegion, country].filter(Boolean);
        const locationStr = [...new Set(parts)].join(', ');
        signLocation.value = locationStr;
        signLocation.removeAttribute('readonly');
        locationStatus.textContent = '(auto-detected)';
        locationStatus.className = 'location-status done';
        $('#preview-location').textContent = locationStr;
      } catch {
        locationStatus.textContent = '(lookup failed)';
        locationStatus.className = 'location-status error';
        signLocation.placeholder = 'Enter location manually';
        signLocation.removeAttribute('readonly');
      }
    },
    (err) => {
      locationStatus.textContent = err.code === 1 ? '(permission denied)' : '(unavailable)';
      locationStatus.className = 'location-status error';
      signLocation.placeholder = 'Enter location manually';
      signLocation.removeAttribute('readonly');
    },
    { enableHighAccuracy: false, timeout: 10000 }
  );
}

refreshLocation.addEventListener('click', detectLocation);

// ─── Reason dropdown ───
function getReasonValue() {
  if (signReason.value === 'Other') return signReasonCustom.value.trim() || 'Other';
  return signReason.value;
}

signReason.addEventListener('change', () => {
  if (signReason.value === 'Other') { signReasonCustom.classList.remove('hidden'); signReasonCustom.focus(); }
  else { signReasonCustom.classList.add('hidden'); }
  $('#preview-reason').textContent = getReasonValue();
});

signReasonCustom.addEventListener('input', () => {
  $('#preview-reason').textContent = getReasonValue();
});

// ─── Step 1: File Upload ───
function handleFile(file) {
  if (!file || file.type !== 'application/pdf') {
    alert('Please select a valid PDF file.');
    return;
  }
  state.pdfFile = file;
  fileName.textContent = file.name;
  fileInfo.classList.remove('hidden');
  dropZone.style.display = 'none';

  const reader = new FileReader();
  reader.onload = async (e) => {
    state.pdfBytes = new Uint8Array(e.target.result);
    state.documentId = generateUUID();
    state.originalHash = await computeSHA256(state.pdfBytes);
    state.browserInfo = getBrowserInfo();
    fetchClientIp();

    const secInfo = $('#security-info');
    if (secInfo) {
      secInfo.classList.remove('hidden');
      $('#doc-id-display').textContent = state.documentId;
      $('#doc-hash-display').textContent = state.originalHash.substring(0, 16) + '...';
      $('#doc-hash-display').title = state.originalHash;
    }

    showSection(detailsSection);
    updateDateTime();
    detectLocation();
    setInterval(updateDateTime, 30000);
  };
  reader.readAsArrayBuffer(file);
}

pdfInput.addEventListener('change', (e) => { if (e.target.files[0]) handleFile(e.target.files[0]); });
dropZone.addEventListener('click', (e) => {
  // Don't double-trigger if clicking the label/input directly
  if (e.target === pdfInput || e.target.closest('.upload-btn')) return;
  pdfInput.click();
});
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('dragover'); });
dropZone.addEventListener('drop', (e) => {
  e.preventDefault(); dropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
});

removeFile.addEventListener('click', () => {
  state.pdfFile = null; state.pdfBytes = null; state.documentId = ''; state.originalHash = '';
  pdfInput.value = ''; fileInfo.classList.add('hidden'); dropZone.style.display = '';
  const secInfo = $('#security-info');
  if (secInfo) secInfo.classList.add('hidden');
  showSection(uploadSection);
});

// ─── Step 2: Signature Details ───
signerName.addEventListener('input', () => {
  $('#preview-name').textContent = signerName.value || 'YOUR NAME';
  validateForm();
});
signLocation.addEventListener('input', () => {
  $('#preview-location').textContent = signLocation.value || '-';
});

function validateForm() {
  proceedBtn.disabled = signerName.value.trim().length === 0;
}

document.querySelectorAll('.sig-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.sig-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.sig-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    $(`#${tab.dataset.tab}-panel`).classList.add('active');
  });
});

// ─── Signature Drawing Canvas ───
let drawing = false, lastX = 0, lastY = 0;

function getCanvasPos(e) {
  const rect = sigCanvas.getBoundingClientRect();
  const clientX = e.touches ? e.touches[0].clientX : e.clientX;
  const clientY = e.touches ? e.touches[0].clientY : e.clientY;
  return {
    x: (clientX - rect.left) * (sigCanvas.width / rect.width),
    y: (clientY - rect.top) * (sigCanvas.height / rect.height)
  };
}
function startDraw(e) { e.preventDefault(); drawing = true; const p = getCanvasPos(e); lastX = p.x; lastY = p.y; }
function draw(e) {
  if (!drawing) return; e.preventDefault();
  const p = getCanvasPos(e);
  sigCtx.beginPath(); sigCtx.moveTo(lastX, lastY); sigCtx.lineTo(p.x, p.y);
  sigCtx.strokeStyle = penColor.value; sigCtx.lineWidth = parseInt(penSize.value);
  sigCtx.lineCap = 'round'; sigCtx.lineJoin = 'round'; sigCtx.stroke();
  lastX = p.x; lastY = p.y;
}
function endDraw() { drawing = false; }

sigCanvas.addEventListener('mousedown', startDraw); sigCanvas.addEventListener('mousemove', draw);
sigCanvas.addEventListener('mouseup', endDraw); sigCanvas.addEventListener('mouseleave', endDraw);
sigCanvas.addEventListener('touchstart', startDraw); sigCanvas.addEventListener('touchmove', draw);
sigCanvas.addEventListener('touchend', endDraw);
clearCanvas.addEventListener('click', () => { sigCtx.clearRect(0, 0, sigCanvas.width, sigCanvas.height); });
document.querySelectorAll('input[name="sig-font"]').forEach(r => {
  r.addEventListener('change', () => { typedSig.style.fontFamily = r.value; });
});

// ─── Step 3: PDF Preview ───
proceedBtn.addEventListener('click', async () => {
  loading.classList.remove('hidden');
  try {
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
    state.pdfDoc = await pdfjsLib.getDocument({ data: state.pdfBytes.slice() }).promise;
    state.totalPages = state.pdfDoc.numPages;
    state.currentPage = 1; state.zoom = 1.0;
    showSection(placementSection);
    await renderPage();
    createSigOverlay();
  } catch (err) { alert('Error loading PDF: ' + err.message); console.error(err); }
  loading.classList.add('hidden');
});

async function renderPage() {
  const page = await state.pdfDoc.getPage(state.currentPage);
  // Fit to container width, render at device pixel ratio for sharp text
  const baseViewport = page.getViewport({ scale: 1.0 });
  const containerWidth = pdfContainer.clientWidth - 32;
  const fitScale = Math.min(containerWidth / baseViewport.width, 2.0) * state.zoom;
  const dpr = window.devicePixelRatio || 1;
  const viewport = page.getViewport({ scale: fitScale * dpr });
  // Canvas internal resolution = high-res
  pdfCanvas.width = viewport.width;
  pdfCanvas.height = viewport.height;
  // CSS display size = logical size (sharp on retina)
  pdfCanvas.style.width = (viewport.width / dpr) + 'px';
  pdfCanvas.style.height = (viewport.height / dpr) + 'px';
  await page.render({ canvasContext: pdfCanvas.getContext('2d'), viewport }).promise;
  pageInfo.textContent = `Page ${state.currentPage} / ${state.totalPages}`;
  prevPage.disabled = state.currentPage <= 1;
  nextPage.disabled = state.currentPage >= state.totalPages;
  zoomLevel.textContent = Math.round(state.zoom * 100) + '%';
}

prevPage.addEventListener('click', async () => { if (state.currentPage > 1) { state.currentPage--; await renderPage(); } });
nextPage.addEventListener('click', async () => { if (state.currentPage < state.totalPages) { state.currentPage++; await renderPage(); } });
zoomIn.addEventListener('click', async () => { state.zoom = Math.min(3, state.zoom + 0.25); await renderPage(); });
zoomOut.addEventListener('click', async () => { state.zoom = Math.max(0.5, state.zoom - 0.25); await renderPage(); });

// ─── Signature Overlay ───
function getSignaturePreviewHtml() {
  const activeTab = document.querySelector('.sig-tab.active').dataset.tab;
  if (activeTab === 'draw') {
    const imgData = sigCtx.getImageData(0, 0, sigCanvas.width, sigCanvas.height);
    const hasContent = imgData.data.some((v, i) => i % 4 === 3 && v > 0);
    if (hasContent) {
      return `<img src="${sigCanvas.toDataURL('image/png')}" style="max-width:120px;max-height:28px;display:block;margin-bottom:2px;">`;
    }
  } else if (activeTab === 'type' && typedSig.value.trim()) {
    const font = document.querySelector('input[name="sig-font"]:checked')?.value || "'Dancing Script', cursive";
    return `<div style="font-family:${font};font-size:18px;color:#1a3b7a;margin-bottom:2px;">${escapeHtml(typedSig.value.trim())}</div>`;
  }
  return '';
}

function createSigOverlay() {
  const name = signerName.value.trim();
  const reason = getReasonValue();
  const location = signLocation.value.trim() || '-';
  const date = signDate.value;
  const sigPreview = getSignaturePreviewHtml();
  sigOverlay.innerHTML = `
    ${sigPreview}
    <div class="sig-stamp">
      <div class="stamp-logo"><span class="sd">Doc</span><span class="ss">Seal</span></div>
      <div class="stamp-details">
        <div><strong>Signed by: ${escapeHtml(name)}</strong></div>
        <div>Reason: ${escapeHtml(reason)}</div>
        <div>Location: ${escapeHtml(location)}</div>
        <div>Date: ${date}</div>
        <div class="stamp-docid">ID: ${state.documentId}</div>
      </div>
    </div>
    <div class="resize-handle"></div>`;
  sigOverlay.classList.remove('hidden');
  const canvasRect = pdfCanvas.getBoundingClientRect();
  sigOverlay.style.left = (pdfCanvas.offsetLeft + canvasRect.width - 290) + 'px';
  sigOverlay.style.top = (pdfCanvas.offsetTop + canvasRect.height - 85) + 'px';
  state.sigPlaced = true; downloadBtn.disabled = false;
  makeDraggable(sigOverlay);
  makeResizable(sigOverlay);
}

function makeDraggable(el) {
  let isDragging = false, startX, startY, origLeft, origTop;
  el.addEventListener('mousedown', (e) => {
    if (e.target.classList.contains('resize-handle')) return;
    isDragging = true; startX = e.clientX; startY = e.clientY;
    origLeft = el.offsetLeft; origTop = el.offsetTop; e.preventDefault();
  });
  document.addEventListener('mousemove', (e) => { if (!isDragging) return; el.style.left = (origLeft + e.clientX - startX) + 'px'; el.style.top = (origTop + e.clientY - startY) + 'px'; });
  document.addEventListener('mouseup', () => { isDragging = false; });
  el.addEventListener('touchstart', (e) => {
    if (e.target.classList.contains('resize-handle')) return;
    isDragging = true; startX = e.touches[0].clientX; startY = e.touches[0].clientY;
    origLeft = el.offsetLeft; origTop = el.offsetTop; e.preventDefault();
  });
  document.addEventListener('touchmove', (e) => { if (!isDragging) return; el.style.left = (origLeft + e.touches[0].clientX - startX) + 'px'; el.style.top = (origTop + e.touches[0].clientY - startY) + 'px'; });
  document.addEventListener('touchend', () => { isDragging = false; });
}

function makeResizable(el) {
  const handle = el.querySelector('.resize-handle');
  if (!handle) return;
  let isResizing = false, startX, startY, origW, origH;

  handle.addEventListener('mousedown', (e) => {
    isResizing = true;
    startX = e.clientX; startY = e.clientY;
    origW = el.offsetWidth; origH = el.offsetHeight;
    e.preventDefault(); e.stopPropagation();
  });
  document.addEventListener('mousemove', (e) => {
    if (!isResizing) return;
    const scale = Math.max(0.5, Math.min(2.0, (origW + e.clientX - startX) / origW));
    el.style.transform = `scale(${scale})`;
    el.style.transformOrigin = 'top left';
    el.dataset.scale = scale;
  });
  document.addEventListener('mouseup', () => { isResizing = false; });

  handle.addEventListener('touchstart', (e) => {
    isResizing = true;
    startX = e.touches[0].clientX; startY = e.touches[0].clientY;
    origW = el.offsetWidth; origH = el.offsetHeight;
    e.preventDefault(); e.stopPropagation();
  });
  document.addEventListener('touchmove', (e) => {
    if (!isResizing) return;
    const scale = Math.max(0.5, Math.min(2.0, (origW + e.touches[0].clientX - startX) / origW));
    el.style.transform = `scale(${scale})`;
    el.style.transformOrigin = 'top left';
    el.dataset.scale = scale;
  });
  document.addEventListener('touchend', () => { isResizing = false; });
}

pdfCanvas.addEventListener('click', (e) => {
  const r = pdfContainer.getBoundingClientRect();
  sigOverlay.style.left = (e.clientX - r.left + pdfContainer.scrollLeft - sigOverlay.offsetWidth / 2) + 'px';
  sigOverlay.style.top = (e.clientY - r.top + pdfContainer.scrollTop - sigOverlay.offsetHeight / 2) + 'px';
  sigOverlay.classList.remove('hidden'); state.sigPlaced = true; downloadBtn.disabled = false;
});

backBtn.addEventListener('click', () => { showSection(detailsSection); });

// ─── Server helpers ───
async function generateQR(data) {
  try {
    const resp = await fetch('/api/qr', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ data }) });
    return (await resp.json()).qr;
  } catch { return null; }
}

async function pkiSignPdf(pdfBytes, meta) {
  try {
    const resp = await fetch('/api/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pdfBytes: Array.from(pdfBytes),
        signer: meta.signer,
        reason: meta.reason,
        location: meta.location,
      })
    });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || 'Signing failed');
    }
    return await resp.json(); // { signedPdf: base64, hash }
  } catch (err) {
    console.error('PKI signing error:', err);
    return null;
  }
}

// ─── Audit Trail Page ───
async function addAuditTrailPage(pdfDoc, audit, qrDataUrl) {
  const { rgb, StandardFonts } = PDFLib;
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);

  const pg = pdfDoc.addPage([595, 842]);
  const w = 595, h = 842;
  let y = h - 50;

  // Header
  pg.drawRectangle({ x: 0, y: h - 80, width: w, height: 80, color: rgb(0.1, 0.23, 0.48) });
  pg.drawText('Doc', { x: 40, y: h - 52, size: 24, font: fontBold, color: rgb(1, 1, 1) });
  pg.drawText('Seal', { x: 40 + fontBold.widthOfTextAtSize('Doc', 24), y: h - 52, size: 24, font: fontBold, color: rgb(0.5, 0.72, 1) });
  pg.drawText('Certificate of Signing', { x: 40 + fontBold.widthOfTextAtSize('DocSeal', 24) + 20, y: h - 50, size: 16, font, color: rgb(0.85, 0.9, 1) });

  y = h - 110;

  function section(title, items) {
    pg.drawText(title, { x: 40, y, size: 12, font: fontBold, color: rgb(0.1, 0.23, 0.48) });
    y -= 4;
    pg.drawLine({ start: { x: 40, y }, end: { x: w - 40, y }, thickness: 1, color: rgb(0.8, 0.85, 0.9) });
    y -= 16;
    for (const [label, value] of items) {
      pg.drawText(label, { x: 50, y, size: 9, font: fontBold, color: rgb(0.3, 0.3, 0.3) });
      const isMono = label.includes('Hash') || label.includes('ID') || label.includes('URL');
      pg.drawText(String(value), { x: 200, y, size: isMono ? 8 : 9, font: isMono ? fontMono : font, color: rgb(0.15, 0.15, 0.15) });
      y -= 16;
    }
    y -= 8;
  }

  section('DOCUMENT INFORMATION', [
    ['Document ID:', audit.documentId],
    ['Original Filename:', audit.fileName],
    ['Original Pages:', String(audit.pageCount)],
    ['Original SHA-256:', audit.originalHash.substring(0, 32)],
    ['', audit.originalHash.substring(32)],
  ]);

  section('SIGNER INFORMATION', [
    ['Signed By:', audit.signerName],
    ['Reason:', audit.reason],
    ['Location:', audit.location],
    ['IP Address:', audit.ip],
    ['Browser / OS:', audit.browserInfo],
    ...(audit.geoCoords ? [['GPS Coordinates:', `${audit.geoCoords.lat}, ${audit.geoCoords.lon}`]] : []),
  ]);

  section('TIMESTAMP', [
    ['Signed At:', audit.timestamp],
    ['Timezone:', Intl.DateTimeFormat().resolvedOptions().timeZone],
    ['Display Format:', audit.displayDate],
  ]);

  section('INTEGRITY & VERIFICATION', [
    ['Hash Algorithm:', 'SHA-256'],
    ['Digital Signature:', 'PKCS#7 (X.509 self-signed certificate)'],
    ['Signature Page:', `Page ${audit.signedOnPage}`],
    ['Verify URL:', VERIFY_URL],
    ['QR Code:', 'Scan to view signing details'],
  ]);

  // QR code
  if (qrDataUrl) {
    try {
      const qrImgBytes = await fetch(qrDataUrl).then(r => r.arrayBuffer());
      const qrImg = await pdfDoc.embedPng(qrImgBytes);
      pg.drawImage(qrImg, { x: w - 180, y: y - 100, width: 130, height: 130 });
      pg.drawText('Scan to verify', { x: w - 165, y: y - 115, size: 9, font, color: rgb(0.4, 0.4, 0.4) });
    } catch (e) { console.error('QR embed failed', e); }
  }

  // Disclaimer
  pg.drawLine({ start: { x: 40, y: 75 }, end: { x: w - 40, y: 75 }, thickness: 0.5, color: rgb(0.7, 0.7, 0.7) });
  pg.drawText('This document was digitally signed using DocSeal with a PKCS#7 digital certificate.', { x: 40, y: 60, size: 8, font, color: rgb(0.5, 0.5, 0.5) });
  pg.drawText(`Verify integrity at: ${VERIFY_URL}`, { x: 40, y: 48, size: 8, font: fontMono, color: rgb(0.4, 0.4, 0.4) });
  pg.drawText('Any modification after signing will invalidate both the hash and the digital signature.', { x: 40, y: 36, size: 8, font, color: rgb(0.5, 0.5, 0.5) });
}

// ─── Generate HTML Verification Certificate ───
function generateHtmlCertificate(audit, signedHash) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DocSeal Signing Certificate - ${audit.documentId}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:#f0f2f5;color:#333;padding:24px}
.cert{max-width:700px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.1);overflow:hidden}
.cert-header{background:linear-gradient(135deg,#1a3b7a,#2d5db8);color:#fff;padding:24px 32px;display:flex;align-items:center;gap:16px}
.cert-header .logo{font-size:28px;font-weight:800;letter-spacing:-0.5px}
.logo-d{color:#fff}.logo-s{color:#7eb8ff;font-weight:600}
.cert-header h1{font-size:18px;font-weight:400;opacity:0.9}
.cert-body{padding:28px 32px}
.badge{display:inline-block;background:#1a3b7a;color:#fff;font-size:10px;font-weight:700;letter-spacing:1px;padding:4px 10px;border-radius:4px;margin-bottom:16px}
.section{margin-bottom:20px}
.section h3{font-size:13px;color:#1a3b7a;text-transform:uppercase;letter-spacing:0.5px;padding-bottom:6px;border-bottom:2px solid #eef3fb;margin-bottom:10px}
.row{display:flex;padding:4px 0;font-size:13px}
.row .label{width:170px;color:#666;font-weight:600;flex-shrink:0}
.row .value{color:#222;word-break:break-all}
.row .mono{font-family:'Courier New',monospace;font-size:12px;color:#1a3b7a}
.verify-section{margin-top:24px;padding:20px;background:#f8fafd;border-radius:10px;border:1px solid #e0e8f0}
.verify-section h3{color:#1a3b7a;margin-bottom:8px;font-size:15px}
.verify-section p{font-size:13px;color:#555;margin-bottom:14px}
.drop-zone{border:2px dashed #b0c4de;border-radius:10px;padding:32px;text-align:center;cursor:pointer;transition:all 0.2s;background:#fff}
.drop-zone:hover,.drop-zone.active{border-color:#1a3b7a;background:#eef3fb}
.drop-zone .icon{font-size:36px;margin-bottom:6px}
.result{margin-top:14px;padding:14px;border-radius:8px;display:none;font-size:14px}
.result.show{display:block}
.result.match{background:#e8f5e9;border:1px solid #66bb6a;color:#2e7d32}
.result.mismatch{background:#ffebee;border:1px solid #ef5350;color:#c62828}
.result.info{background:#e3f2fd;border:1px solid #42a5f5;color:#1565c0}
.result .hash{font-family:'Courier New',monospace;font-size:11px;word-break:break-all;margin-top:6px;padding:8px;background:rgba(0,0,0,0.04);border-radius:4px}
footer{text-align:center;padding:16px;color:#aaa;font-size:11px}
@media print{.verify-section{display:none}body{background:#fff;padding:0}.cert{box-shadow:none}}
</style>
</head>
<body>
<div class="cert">
  <div class="cert-header">
    <div class="logo"><span class="logo-d">Doc</span><span class="logo-s">Seal</span></div>
    <h1>Certificate of Signing</h1>
  </div>
  <div class="cert-body">
    <span class="badge">DIGITALLY SIGNED</span>

    <div class="section">
      <h3>Document</h3>
      <div class="row"><span class="label">Document ID</span><span class="value mono">${escapeHtml(audit.documentId)}</span></div>
      <div class="row"><span class="label">Filename</span><span class="value">${escapeHtml(audit.fileName)}</span></div>
      <div class="row"><span class="label">Original Pages</span><span class="value">${escapeHtml(String(audit.pageCount))}</span></div>
      <div class="row"><span class="label">Original Doc SHA-256</span><span class="value mono">${escapeHtml(audit.originalHash)}</span></div>
    </div>

    <div class="section">
      <h3>Signer</h3>
      <div class="row"><span class="label">Signed By</span><span class="value">${escapeHtml(audit.signerName)}</span></div>
      <div class="row"><span class="label">Reason</span><span class="value">${escapeHtml(audit.reason)}</span></div>
      <div class="row"><span class="label">Location</span><span class="value">${escapeHtml(audit.location)}</span></div>
      <div class="row"><span class="label">IP Address</span><span class="value mono">${escapeHtml(audit.ip)}</span></div>
      <div class="row"><span class="label">Browser / OS</span><span class="value">${escapeHtml(audit.browserInfo)}</span></div>
      ${audit.geoCoords ? `<div class="row"><span class="label">GPS Coordinates</span><span class="value mono">${escapeHtml(audit.geoCoords.lat)}, ${escapeHtml(audit.geoCoords.lon)}</span></div>` : ''}
    </div>

    <div class="section">
      <h3>Timestamp</h3>
      <div class="row"><span class="label">Signed At</span><span class="value">${escapeHtml(audit.timestamp)}</span></div>
      <div class="row"><span class="label">Display Date</span><span class="value">${escapeHtml(audit.displayDate)}</span></div>
    </div>

    <div class="section">
      <h3>Integrity</h3>
      <div class="row"><span class="label">Signed File SHA-256</span><span class="value mono">${signedHash}</span></div>
      <div class="row"><span class="label">Digital Signature</span><span class="value">PKCS#7 (X.509 certificate)</span></div>
      <div class="row"><span class="label">Verify Online</span><span class="value"><a href="${VERIFY_URL}" target="_blank">${VERIFY_URL}</a></span></div>
    </div>

    <div class="verify-section">
      <h3>Verify This Document</h3>
      <p>Drop the signed PDF below to instantly check if it matches this certificate. Everything runs in your browser &mdash; no upload.</p>
      <div class="drop-zone" id="vdrop">
        <div class="icon">&#128270;</div>
        <p>Drop the signed PDF here</p>
        <input type="file" id="vfile" accept=".pdf" hidden>
      </div>
      <div class="result" id="vresult"></div>
    </div>
  </div>
</div>
<footer>DocSeal &mdash; ManDarshan AI Solutions &mdash; This certificate was generated at the time of signing.</footer>

<script>
const expectedHash = "${signedHash}";
const dz = document.getElementById('vdrop');
const fi = document.getElementById('vfile');
const vr = document.getElementById('vresult');
dz.addEventListener('click', () => fi.click());
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('active'); });
dz.addEventListener('dragleave', () => dz.classList.remove('active'));
dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('active'); if(e.dataTransfer.files[0]) check(e.dataTransfer.files[0]); });
fi.addEventListener('change', e => { if(e.target.files[0]) check(e.target.files[0]); });
async function check(file) {
  const buf = await file.arrayBuffer();
  const hb = await crypto.subtle.digest('SHA-256', buf);
  const hash = Array.from(new Uint8Array(hb)).map(b=>b.toString(16).padStart(2,'0')).join('');
  if (hash === expectedHash) {
    vr.className = 'result show match';
    vr.innerHTML = '<strong>MATCH</strong> &mdash; This document is authentic and has not been tampered with.';
  } else {
    vr.className = 'result show mismatch';
    vr.innerHTML = '<strong>MISMATCH</strong> &mdash; This document may have been modified after signing.<div class="hash">Expected: '+expectedHash+'<br>Got: '+hash+'</div>';
  }
}
</script>
</body>
</html>`;
}

// ─── Download helper ───
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}

// ─── Main: Generate Signed PDF ───
downloadBtn.addEventListener('click', async () => {
  if (!state.sigPlaced) return;
  loading.classList.remove('hidden');
  const loadingText = loading.querySelector('p');

  try {
    const { PDFDocument, rgb, StandardFonts } = PDFLib;
    const pdfDoc = await PDFDocument.load(state.pdfBytes);
    const pages = pdfDoc.getPages();
    const page = pages[state.currentPage - 1];
    const { width: pageWidth, height: pageHeight } = page.getSize();

    // Fixed stamp size in PDF points, scaled by user resize
    const userScale = parseFloat(sigOverlay.dataset.scale || '1');
    const stampW = Math.round(250 * userScale);
    const stampH = Math.round(65 * userScale);

    // Map overlay position to PDF coordinates
    // Both overlay and canvas are positioned within pdf-container (overflow:auto)
    // Use offsetLeft/Top which are relative to the container's scroll content
    const canvasCSSW = parseFloat(pdfCanvas.style.width);
    const canvasCSSH = parseFloat(pdfCanvas.style.height);

    // Overlay position relative to canvas within the container
    const ox = sigOverlay.offsetLeft - pdfCanvas.offsetLeft;
    const oy = sigOverlay.offsetTop - pdfCanvas.offsetTop;

    // As fraction of canvas CSS dimensions
    const relX = ox / canvasCSSW;
    const relY = oy / canvasCSSH;

    // Map to PDF coordinates (PDF origin = bottom-left)
    let pdfX = Math.max(5, Math.min(relX * pageWidth, pageWidth - stampW - 5));
    let pdfY = Math.max(5, Math.min(pageHeight - (relY * pageHeight) - stampH, pageHeight - stampH - 5));

    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
    const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);

    const name = signerName.value.trim();
    const reason = getReasonValue();
    const location = signLocation.value.trim() || '-';
    const date = signDate.value;
    const timestamp = formatFullTimestamp();

    // ── Visual Signature Stamp ──
    loadingText.textContent = 'Adding signature stamp...';
    const fs = 7 * userScale, lh = 9.5 * userScale, logoFs = 12 * userScale;

    page.drawRectangle({ x: pdfX, y: pdfY, width: stampW, height: stampH, color: rgb(1,1,1), borderColor: rgb(0.1,0.23,0.48), borderWidth: 1 });

    const p = 5 * userScale; // padding scale
    const logoX = pdfX + p, logoY = pdfY + stampH / 2 - logoFs / 3;
    page.drawText('Doc', { x: logoX, y: logoY, size: logoFs, font: fontBold, color: rgb(0.1,0.23,0.48) });
    page.drawText('Seal', { x: logoX + fontBold.widthOfTextAtSize('Doc', logoFs), y: logoY, size: logoFs, font: fontBold, color: rgb(0.18,0.37,0.72) });

    const divX = logoX + 42 * userScale;
    page.drawLine({ start: { x: divX, y: pdfY + 4 }, end: { x: divX, y: pdfY + stampH - 4 }, thickness: 0.7, color: rgb(0.1,0.23,0.48) });

    const tx = divX + 5 * userScale;
    let ty = pdfY + stampH - 9 * userScale;
    page.drawText('Signed by: ', { x: tx, y: ty, size: fs, font, color: rgb(0.2,0.2,0.2) });
    page.drawText(name, { x: tx + font.widthOfTextAtSize('Signed by: ', fs), y: ty, size: fs, font: fontBold, color: rgb(0.1,0.1,0.1) });
    ty -= lh; page.drawText(`Reason: ${reason}`, { x: tx, y: ty, size: fs, font, color: rgb(0.2,0.2,0.2) });
    ty -= lh; page.drawText(`Location: ${location}`, { x: tx, y: ty, size: fs, font, color: rgb(0.2,0.2,0.2) });
    ty -= lh; page.drawText(`Date: ${date}`, { x: tx, y: ty, size: fs, font, color: rgb(0.2,0.2,0.2) });
    ty -= lh; page.drawText(`ID: ${state.documentId}`, { x: tx, y: ty, size: 5.5 * userScale, font: fontMono, color: rgb(0.5,0.5,0.5) });

    // Drawn signature above stamp
    const drawnSig = getDrawnSignatureDataUrl();
    if (drawnSig) {
      const sigImgBytes = await fetch(drawnSig).then(r => r.arrayBuffer());
      const sigImg = await pdfDoc.embedPng(sigImgBytes);
      const sigW = 120 * userScale, sigH = Math.min(sigW / (sigImg.width / sigImg.height), 30 * userScale);
      page.drawImage(sigImg, { x: pdfX + 3, y: pdfY + stampH + 2, width: sigW, height: sigH });
    }

    // Typed signature above stamp
    const activeTab = document.querySelector('.sig-tab.active').dataset.tab;
    if (activeTab === 'type' && typedSig.value.trim()) {
      const italic = await pdfDoc.embedFont(StandardFonts.HelveticaOblique);
      page.drawText(typedSig.value.trim(), { x: pdfX + 3, y: pdfY + stampH + 4, size: 12 * userScale, font: italic, color: rgb(0.1,0.23,0.48) });
    }

    // QR code on stamp
    loadingText.textContent = 'Generating QR code...';
    const qrPayload = JSON.stringify({ id: state.documentId, signer: name, reason, location, date: timestamp, hash: state.originalHash.substring(0, 32), verify: VERIFY_URL });
    const qrDataUrl = await generateQR(qrPayload);
    if (qrDataUrl) {
      try {
        const qrBytes = await fetch(qrDataUrl).then(r => r.arrayBuffer());
        const qrImg = await pdfDoc.embedPng(qrBytes);
        const qrSz = Math.round(38 * userScale);
        page.drawImage(qrImg, { x: pdfX + stampW - qrSz - 3, y: pdfY + (stampH - qrSz) / 2, width: qrSz, height: qrSz });
      } catch (e) { console.error('QR embed failed', e); }
    }

    // ── Audit Trail Page ──
    loadingText.textContent = 'Building audit trail...';
    const audit = {
      documentId: state.documentId, fileName: state.pdfFile.name, pageCount: state.totalPages,
      originalHash: state.originalHash, signerName: name, reason, location,
      ip: state.clientIp, browserInfo: state.browserInfo, geoCoords: state.geoCoords,
      timestamp, displayDate: date, signedOnPage: state.currentPage,
    };
    await addAuditTrailPage(pdfDoc, audit, qrDataUrl);

    // ── Save stamped PDF ──
    const stampedBytes = await pdfDoc.save({ useObjectStreams: false });

    // ── PKI Digital Signature via server ──
    loadingText.textContent = 'Applying digital certificate...';
    const pkiResult = await pkiSignPdf(new Uint8Array(stampedBytes), { signer: name, reason, location });

    let finalPdfBytes, finalHash;
    if (pkiResult) {
      // Server signed successfully
      finalPdfBytes = Uint8Array.from(atob(pkiResult.signedPdf), c => c.charCodeAt(0));
      finalHash = pkiResult.hash;
    } else {
      // Fallback: use the stamped PDF without PKI (still has audit trail + QR)
      finalPdfBytes = new Uint8Array(stampedBytes);
      finalHash = await computeSHA256(finalPdfBytes);
      console.warn('PKI signing unavailable, using visual signature only');
    }

    // ── Download signed PDF ──
    loadingText.textContent = 'Downloading files...';
    downloadBlob(new Blob([finalPdfBytes], { type: 'application/pdf' }), `signed_${state.pdfFile.name}`);

    // ── Generate & download HTML certificate ──
    const htmlCert = generateHtmlCertificate(audit, finalHash);
    const certFilename = `certificate_${state.documentId}.html`;
    setTimeout(() => {
      downloadBlob(new Blob([htmlCert], { type: 'text/html' }), certFilename);
    }, 500);

    // ── Show success dialog ──
    loading.classList.add('hidden');
    loadingText.textContent = 'Processing your PDF...';
    showHashDialog(finalHash, state.documentId, !!pkiResult, certFilename);
    return;

  } catch (err) {
    alert('Error generating signed PDF: ' + err.message);
    console.error(err);
  }
  loading.classList.add('hidden');
  loadingText.textContent = 'Processing your PDF...';
});

function getDrawnSignatureDataUrl() {
  const activeTab = document.querySelector('.sig-tab.active').dataset.tab;
  if (activeTab !== 'draw') return null;
  const imageData = sigCtx.getImageData(0, 0, sigCanvas.width, sigCanvas.height);
  const hasContent = imageData.data.some((val, i) => i % 4 === 3 && val > 0);
  if (!hasContent) return null;
  return sigCanvas.toDataURL('image/png');
}

// ─── Success Dialog ───
function showHashDialog(hash, docId, hasPki, certFile) {
  const existing = $('#hash-dialog');
  if (existing) existing.remove();

  const pkiStatus = hasPki
    ? '<span style="color:#2e7d32;font-weight:600">Digital certificate applied</span> &mdash; Adobe Reader will validate this signature.'
    : '<span style="color:#e65100;font-weight:600">Visual signature only</span> &mdash; PKI certificate was not available.';

  const dialog = document.createElement('div');
  dialog.id = 'hash-dialog';
  dialog.className = 'hash-dialog';
  dialog.innerHTML = `
    <div class="hash-dialog-content">
      <h3>Document Signed Successfully</h3>
      <p>Two files have been downloaded:</p>
      <div style="background:#f5f7fa;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px;">
        <div><strong>1.</strong> signed_${escapeHtml(state.pdfFile.name)} &mdash; your signed PDF</div>
        <div><strong>2.</strong> ${escapeHtml(certFile)} &mdash; verification certificate (HTML)</div>
      </div>
      <div style="font-size:13px;margin-bottom:16px;">${pkiStatus}</div>
      <div class="hash-row">
        <span class="hash-label">Document ID</span>
        <code class="hash-value">${escapeHtml(docId)}</code>
      </div>
      <div class="hash-row">
        <span class="hash-label">Signed File SHA-256</span>
        <code class="hash-value hash-long">${escapeHtml(hash)}</code>
      </div>
      <div class="hash-actions">
        <button class="btn-secondary" id="copy-hash-btn">Copy Hash</button>
        <button class="btn-secondary" id="verify-online-btn">Verify Online</button>
        <button class="btn-primary" id="done-dialog-btn">Done</button>
      </div>
    </div>`;
  document.body.appendChild(dialog);
  // Attach event listeners programmatically (no inline onclick with interpolated data)
  document.getElementById('copy-hash-btn').addEventListener('click', function() { navigator.clipboard.writeText(hash); this.textContent = 'Copied!'; });
  document.getElementById('verify-online-btn').addEventListener('click', () => window.open(VERIFY_URL, '_blank'));
  document.getElementById('done-dialog-btn').addEventListener('click', () => dialog.remove());
}

// ─── Init ───
updateDateTime();
validateForm();
