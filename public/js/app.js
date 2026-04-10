// ─── State ───
const state = {
  pdfFile: null,
  pdfBytes: null,
  pdfDoc: null,
  currentPage: 1,
  totalPages: 1,
  zoom: 1.0,
  sigPlaced: false,
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

function updateDateTime() {
  const now = formatDate();
  signDate.value = now;
  $('#preview-date').textContent = now;
}

function showSection(section) {
  [uploadSection, detailsSection, placementSection].forEach(s => s.classList.add('hidden'));
  section.classList.remove('hidden');
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

        // Build location string: "City, State, Country" or "City, Country"
        const parts = [city, stateRegion, country].filter(Boolean);
        // Remove duplicates (some APIs return state === city)
        const unique = [...new Set(parts)];
        const locationStr = unique.join(', ');

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
      // User denied or error
      locationStatus.textContent = err.code === 1 ? '(permission denied)' : '(unavailable)';
      locationStatus.className = 'location-status error';
      signLocation.placeholder = 'Enter location manually';
      signLocation.removeAttribute('readonly');
    },
    { enableHighAccuracy: false, timeout: 10000 }
  );
}

refreshLocation.addEventListener('click', detectLocation);

// ─── Reason dropdown with "Other" custom input ───
function getReasonValue() {
  if (signReason.value === 'Other') {
    return signReasonCustom.value.trim() || 'Other';
  }
  return signReason.value;
}

signReason.addEventListener('change', () => {
  if (signReason.value === 'Other') {
    signReasonCustom.classList.remove('hidden');
    signReasonCustom.focus();
  } else {
    signReasonCustom.classList.add('hidden');
  }
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
    showSection(detailsSection);
    updateDateTime();
    detectLocation();
    setInterval(updateDateTime, 30000);
  };
  reader.readAsArrayBuffer(file);
}

pdfInput.addEventListener('change', (e) => {
  if (e.target.files[0]) handleFile(e.target.files[0]);
});

dropZone.addEventListener('click', () => pdfInput.click());

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
});

removeFile.addEventListener('click', () => {
  state.pdfFile = null;
  state.pdfBytes = null;
  pdfInput.value = '';
  fileInfo.classList.add('hidden');
  dropZone.style.display = '';
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

// Signature tabs
document.querySelectorAll('.sig-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.sig-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.sig-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    $(`#${tab.dataset.tab}-panel`).classList.add('active');
  });
});

// ─── Signature Drawing Canvas ───
let drawing = false;
let lastX = 0, lastY = 0;

function getCanvasPos(e) {
  const rect = sigCanvas.getBoundingClientRect();
  const scaleX = sigCanvas.width / rect.width;
  const scaleY = sigCanvas.height / rect.height;
  const clientX = e.touches ? e.touches[0].clientX : e.clientX;
  const clientY = e.touches ? e.touches[0].clientY : e.clientY;
  return {
    x: (clientX - rect.left) * scaleX,
    y: (clientY - rect.top) * scaleY
  };
}

function startDraw(e) {
  e.preventDefault();
  drawing = true;
  const pos = getCanvasPos(e);
  lastX = pos.x;
  lastY = pos.y;
}

function draw(e) {
  if (!drawing) return;
  e.preventDefault();
  const pos = getCanvasPos(e);
  sigCtx.beginPath();
  sigCtx.moveTo(lastX, lastY);
  sigCtx.lineTo(pos.x, pos.y);
  sigCtx.strokeStyle = penColor.value;
  sigCtx.lineWidth = parseInt(penSize.value);
  sigCtx.lineCap = 'round';
  sigCtx.lineJoin = 'round';
  sigCtx.stroke();
  lastX = pos.x;
  lastY = pos.y;
}

function endDraw() {
  drawing = false;
}

sigCanvas.addEventListener('mousedown', startDraw);
sigCanvas.addEventListener('mousemove', draw);
sigCanvas.addEventListener('mouseup', endDraw);
sigCanvas.addEventListener('mouseleave', endDraw);
sigCanvas.addEventListener('touchstart', startDraw);
sigCanvas.addEventListener('touchmove', draw);
sigCanvas.addEventListener('touchend', endDraw);

clearCanvas.addEventListener('click', () => {
  sigCtx.clearRect(0, 0, sigCanvas.width, sigCanvas.height);
});

// Typed signature font change
document.querySelectorAll('input[name="sig-font"]').forEach(radio => {
  radio.addEventListener('change', () => {
    typedSig.style.fontFamily = radio.value;
  });
});

// ─── Step 3: Proceed to Placement ───
proceedBtn.addEventListener('click', async () => {
  loading.classList.remove('hidden');
  try {
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
    state.pdfDoc = await pdfjsLib.getDocument({ data: state.pdfBytes.slice() }).promise;
    state.totalPages = state.pdfDoc.numPages;
    state.currentPage = 1;
    state.zoom = 1.0;

    showSection(placementSection);
    await renderPage();
    createSigOverlay();
  } catch (err) {
    alert('Error loading PDF: ' + err.message);
    console.error(err);
  }
  loading.classList.add('hidden');
});

async function renderPage() {
  const page = await state.pdfDoc.getPage(state.currentPage);
  const viewport = page.getViewport({ scale: state.zoom * 1.5 });
  pdfCanvas.width = viewport.width;
  pdfCanvas.height = viewport.height;

  await page.render({
    canvasContext: pdfCanvas.getContext('2d'),
    viewport
  }).promise;

  pageInfo.textContent = `Page ${state.currentPage} / ${state.totalPages}`;
  prevPage.disabled = state.currentPage <= 1;
  nextPage.disabled = state.currentPage >= state.totalPages;
  zoomLevel.textContent = Math.round(state.zoom * 100) + '%';
}

prevPage.addEventListener('click', async () => {
  if (state.currentPage > 1) { state.currentPage--; await renderPage(); }
});
nextPage.addEventListener('click', async () => {
  if (state.currentPage < state.totalPages) { state.currentPage++; await renderPage(); }
});
zoomIn.addEventListener('click', async () => {
  state.zoom = Math.min(3, state.zoom + 0.25); await renderPage();
});
zoomOut.addEventListener('click', async () => {
  state.zoom = Math.max(0.5, state.zoom - 0.25); await renderPage();
});

// ─── Signature Overlay (draggable stamp on PDF) ───
function createSigOverlay() {
  const name = signerName.value.trim();
  const reason = getReasonValue();
  const location = signLocation.value.trim() || '-';
  const date = signDate.value;

  sigOverlay.innerHTML = `
    <div class="sig-stamp">
      <div class="stamp-logo"><span class="sd">Doc</span><span class="ss">Seal</span></div>
      <div class="stamp-details">
        <div><strong>Signed by: ${escapeHtml(name)}</strong></div>
        <div>Reason: ${escapeHtml(reason)}</div>
        <div>Location: ${escapeHtml(location)}</div>
        <div>Date: ${date}</div>
      </div>
    </div>
    <div class="resize-handle"></div>
  `;

  sigOverlay.classList.remove('hidden');

  const offsetX = pdfCanvas.offsetLeft;
  const canvasRect = pdfCanvas.getBoundingClientRect();
  const offsetY = pdfCanvas.offsetTop;

  sigOverlay.style.left = (offsetX + canvasRect.width - 320) + 'px';
  sigOverlay.style.top = (offsetY + canvasRect.height - 80) + 'px';

  state.sigPlaced = true;
  downloadBtn.disabled = false;
  makeDraggable(sigOverlay);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function makeDraggable(el) {
  let isDragging = false;
  let startX, startY, origLeft, origTop;

  el.addEventListener('mousedown', (e) => {
    if (e.target.classList.contains('resize-handle')) return;
    isDragging = true;
    startX = e.clientX;
    startY = e.clientY;
    origLeft = el.offsetLeft;
    origTop = el.offsetTop;
    e.preventDefault();
  });

  document.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    el.style.left = (origLeft + e.clientX - startX) + 'px';
    el.style.top = (origTop + e.clientY - startY) + 'px';
  });

  document.addEventListener('mouseup', () => { isDragging = false; });

  el.addEventListener('touchstart', (e) => {
    if (e.target.classList.contains('resize-handle')) return;
    isDragging = true;
    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
    origLeft = el.offsetLeft;
    origTop = el.offsetTop;
    e.preventDefault();
  });

  document.addEventListener('touchmove', (e) => {
    if (!isDragging) return;
    el.style.left = (origLeft + e.touches[0].clientX - startX) + 'px';
    el.style.top = (origTop + e.touches[0].clientY - startY) + 'px';
  });

  document.addEventListener('touchend', () => { isDragging = false; });
}

// Click on PDF to reposition signature
pdfCanvas.addEventListener('click', (e) => {
  const containerRect = pdfContainer.getBoundingClientRect();
  const clickX = e.clientX - containerRect.left + pdfContainer.scrollLeft;
  const clickY = e.clientY - containerRect.top + pdfContainer.scrollTop;

  sigOverlay.style.left = (clickX - sigOverlay.offsetWidth / 2) + 'px';
  sigOverlay.style.top = (clickY - sigOverlay.offsetHeight / 2) + 'px';
  sigOverlay.classList.remove('hidden');

  state.sigPlaced = true;
  downloadBtn.disabled = false;
});

backBtn.addEventListener('click', () => {
  showSection(detailsSection);
});

// ─── Generate Signed PDF ───
downloadBtn.addEventListener('click', async () => {
  if (!state.sigPlaced) return;
  loading.classList.remove('hidden');

  try {
    const { PDFDocument, rgb, StandardFonts } = PDFLib;
    const pdfDoc = await PDFDocument.load(state.pdfBytes);
    const pages = pdfDoc.getPages();
    const page = pages[state.currentPage - 1];
    const { width: pageWidth, height: pageHeight } = page.getSize();

    const canvasRect = pdfCanvas.getBoundingClientRect();
    const overlayRect = sigOverlay.getBoundingClientRect();

    const relX = (overlayRect.left - canvasRect.left) / canvasRect.width;
    const relY = (overlayRect.top - canvasRect.top) / canvasRect.height;
    const relW = overlayRect.width / canvasRect.width;
    const relH = overlayRect.height / canvasRect.height;

    // PDF coordinates (origin = bottom-left)
    const pdfX = relX * pageWidth;
    const pdfY = pageHeight - (relY * pageHeight) - (relH * pageHeight);
    const stampW = relW * pageWidth;
    const stampH = relH * pageHeight;

    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

    const name = signerName.value.trim();
    const reason = getReasonValue();
    const location = signLocation.value.trim() || '-';
    const date = signDate.value;

    const padding = 6;
    const fontSize = 8;
    const lineHeight = 12;
    const logoFontSize = 16;

    // Background box
    page.drawRectangle({
      x: pdfX,
      y: pdfY,
      width: stampW,
      height: stampH,
      color: rgb(1, 1, 1),
      borderColor: rgb(0.1, 0.23, 0.48),
      borderWidth: 1.5,
    });

    // "DocSeal" logo
    const logoX = pdfX + padding + 2;
    const logoY = pdfY + stampH / 2 - logoFontSize / 3;

    page.drawText('Doc', {
      x: logoX,
      y: logoY,
      size: logoFontSize,
      font: fontBold,
      color: rgb(0.1, 0.23, 0.48),
    });

    page.drawText('Seal', {
      x: logoX + fontBold.widthOfTextAtSize('Doc', logoFontSize),
      y: logoY,
      size: logoFontSize,
      font: fontBold,
      color: rgb(0.18, 0.37, 0.72),
    });

    // Divider line
    const dividerX = logoX + 52;
    page.drawLine({
      start: { x: dividerX, y: pdfY + 4 },
      end: { x: dividerX, y: pdfY + stampH - 4 },
      thickness: 1,
      color: rgb(0.1, 0.23, 0.48),
    });

    // Text details
    const textX = dividerX + 8;
    let textY = pdfY + stampH - padding - fontSize;

    page.drawText('Signed by: ', {
      x: textX, y: textY, size: fontSize, font,
      color: rgb(0.2, 0.2, 0.2),
    });
    page.drawText(name, {
      x: textX + font.widthOfTextAtSize('Signed by: ', fontSize),
      y: textY, size: fontSize, font: fontBold,
      color: rgb(0.1, 0.1, 0.1),
    });

    textY -= lineHeight;
    page.drawText(`Reason: ${reason}`, {
      x: textX, y: textY, size: fontSize, font,
      color: rgb(0.2, 0.2, 0.2),
    });

    textY -= lineHeight;
    page.drawText(`Location: ${location}`, {
      x: textX, y: textY, size: fontSize, font,
      color: rgb(0.2, 0.2, 0.2),
    });

    textY -= lineHeight;
    page.drawText(`Date: ${date}`, {
      x: textX, y: textY, size: fontSize, font,
      color: rgb(0.2, 0.2, 0.2),
    });

    // Embed drawn signature above the stamp
    const drawnSigDataUrl = getDrawnSignatureDataUrl();
    if (drawnSigDataUrl) {
      const sigImgBytes = await fetch(drawnSigDataUrl).then(r => r.arrayBuffer());
      const sigImg = await pdfDoc.embedPng(sigImgBytes);
      const sigAspect = sigImg.width / sigImg.height;
      const sigDrawW = stampW - 10;
      const sigDrawH = sigDrawW / sigAspect;
      page.drawImage(sigImg, {
        x: pdfX + 5,
        y: pdfY + stampH + 4,
        width: sigDrawW,
        height: Math.min(sigDrawH, 40),
      });
    }

    // Embed typed signature above the stamp
    const activeTab = document.querySelector('.sig-tab.active').dataset.tab;
    if (activeTab === 'type' && typedSig.value.trim()) {
      const italicFont = await pdfDoc.embedFont(StandardFonts.HelveticaOblique);
      page.drawText(typedSig.value.trim(), {
        x: pdfX + 5,
        y: pdfY + stampH + 8,
        size: 16,
        font: italicFont,
        color: rgb(0.1, 0.23, 0.48),
      });
    }

    const signedPdfBytes = await pdfDoc.save();

    // Download
    const blob = new Blob([signedPdfBytes], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `signed_${state.pdfFile.name}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

  } catch (err) {
    alert('Error generating signed PDF: ' + err.message);
    console.error(err);
  }

  loading.classList.add('hidden');
});

function getDrawnSignatureDataUrl() {
  const activeTab = document.querySelector('.sig-tab.active').dataset.tab;
  if (activeTab !== 'draw') return null;
  const imageData = sigCtx.getImageData(0, 0, sigCanvas.width, sigCanvas.height);
  const hasContent = imageData.data.some((val, i) => i % 4 === 3 && val > 0);
  if (!hasContent) return null;
  return sigCanvas.toDataURL('image/png');
}

// ─── Init ───
updateDateTime();
validateForm();
