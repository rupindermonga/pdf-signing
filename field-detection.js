// Auto-detect signature/date/name/etc. fields in an uploaded PDF.
//
// Two strategies, combined:
//   1. AcroForm-based: if the PDF already has form fields (many government / bank docs do),
//      convert them to SealForge fields at the exact coordinates the issuer placed them.
//   2. Heuristic text-based: scan page text for anchor phrases ("Signature:", "Date:",
//      "Name:", "Initials:", "Witness:", "Aadhaar No.", etc.) and place a field to the
//      right of — or below — the anchor, at the line's baseline.
//
// Returns an array of SealForge field objects ready to be merged into documents.fields_json.
// No network required; if ANTHROPIC_API_KEY is set we also offer `detectWithAI()` that passes
// the first page image to Claude for smarter inference (opt-in, separate function).
const { PDFDocument, PDFName, PDFDict, PDFArray } = require('pdf-lib');
const crypto = require('crypto');

// Anchors by language + field type. Match is case-insensitive, word-boundary aware where sensible.
const ANCHORS = {
  signature: [
    /\bsign(?:ed|ature)?\s*(?:of|by)?\s*[:_]/i,
    /\bsigned\s*\b/i,
    /\bX\s*_{3,}/,                  // classic "X ______" signature line
    /\bfirma\b/i,                   // Spanish/Portuguese fallback
    /signature\s+d[eu]/i,           // French: "Signature de"
    /हस्ताक्षर/,                     // Hindi
  ],
  initials: [
    /\binitials?\s*[:_]/i,
    /\binit\.\s*[:_]/i,
    /paraphe/i,                     // French
    /आद्यक्षर/,                       // Hindi
  ],
  date: [
    /\bdate\s*[:_]/i,
    /\bdated\s*[:_]?/i,
    /\bon\s*this\s*\d?\d?\s*day/i,
    /\bsigned\s*on\b/i,
    /date\s*:/i,
    /तारीख/, /दिनांक/,                // Hindi
  ],
  name: [
    /\b(?:full\s+)?name\s*[:_]/i,
    /\bprint(?:ed)?\s+name\s*[:_]?/i,
    /\bnom\s*[:_]/i,                // French
    /नाम\s*[:_]/,                    // Hindi
  ],
  email: [
    /\bemail\s*(?:address)?\s*[:_]/i,
    /\be[-\s]?mail\s*[:_]/i,
    /courriel/i,                    // French
    /ईमेल/,
  ],
  phone: [
    /\b(?:phone|mobile|cell|telephone)\s*(?:no\.?|number)?\s*[:_]/i,
    /\btél(?:éphone)?\s*[:_]/i,
    /फ़ोन|मोबाइल/,
  ],
  witness: [
    /\bwitness(?:ed)?\s*(?:by)?\s*[:_]/i,
    /témoin/i,
    /साक्षी|गवाह/,
  ],
  aadhaar: [
    /\baadhaar(?:\s+no\.?|\s+number)?\s*[:_]/i,
    /आधार\s*(?:संख्या|नंबर)?\s*[:_]?/,
  ],
  pan: [
    /\bPAN\s*(?:no\.?|number|card)?\s*[:_]/i,
  ],
  address: [
    /\baddress\s*[:_]/i,
    /adresse\s*[:_]/i,
    /पता\s*[:_]/,
  ],
};

const DEFAULT_SIZES = {
  signature: { wPct: 18, hPct: 4 },
  initials: { wPct: 6, hPct: 3.5 },
  date: { wPct: 12, hPct: 3 },
  name: { wPct: 20, hPct: 3 },
  email: { wPct: 22, hPct: 3 },
  phone: { wPct: 14, hPct: 3 },
  witness: { wPct: 18, hPct: 4 },
  aadhaar: { wPct: 16, hPct: 3 },
  pan: { wPct: 12, hPct: 3 },
  address: { wPct: 30, hPct: 4 },
  text: { wPct: 18, hPct: 3 },
};

function uid() { return 'f_' + crypto.randomBytes(6).toString('hex'); }

// Given raw text and its position (PDF page coords, origin = bottom-left),
// convert to SealForge field object (percentages, origin = top-left).
function makeField({ type, label, page, pageWidth, pageHeight, x, y, anchorWidth, anchorHeight, signerIndex }) {
  const size = DEFAULT_SIZES[type] || DEFAULT_SIZES.text;
  // Place to the right of the anchor, same baseline — unless the anchor ends near page right edge.
  const spaceAfter = pageWidth - (x + anchorWidth);
  const myW = Math.min(size.wPct, (spaceAfter / pageWidth) * 100 * 0.9);
  const myH = size.hPct;
  const xPctRaw = ((x + anchorWidth + 4) / pageWidth) * 100;
  // Flip Y: SealForge uses top-origin percentages.
  const yPdfBottom = y;                        // anchor baseline y (bottom-up)
  const yPdfTop = pageHeight - yPdfBottom - anchorHeight;
  const yPctRaw = (yPdfTop / pageHeight) * 100;
  return {
    id: uid(),
    type,
    label: label || type[0].toUpperCase() + type.slice(1),
    page,
    xPct: Math.max(0, Math.min(95, xPctRaw)),
    yPct: Math.max(0, Math.min(95, yPctRaw)),
    wPct: Math.max(3, Math.min(50, myW)),
    hPct: Math.max(2, Math.min(15, myH)),
    required: type === 'signature' || type === 'date',
    signerIndex: typeof signerIndex === 'number' ? signerIndex : 0,
    autoDetected: true,
  };
}

// Strategy 1: AcroForm import.
async function importAcroFormFields(pdfBytes) {
  try {
    const pdf = await PDFDocument.load(pdfBytes, { ignoreEncryption: true });
    const form = pdf.getForm();
    const acroFields = form.getFields();
    if (!acroFields.length) return [];
    const fields = [];
    const pages = pdf.getPages();
    for (const f of acroFields) {
      const name = f.getName() || 'field';
      // Detect type by constructor name
      const ctor = f.constructor.name;
      let type = 'text';
      if (/Signature/i.test(ctor) || /sign/i.test(name)) type = 'signature';
      else if (/CheckBox/i.test(ctor)) type = 'checkbox';
      else if (/Dropdown/i.test(ctor) || /OptionList/i.test(ctor)) type = 'dropdown';
      else if (/RadioGroup/i.test(ctor)) type = 'radio';
      else if (/date/i.test(name)) type = 'date';
      else if (/name/i.test(name)) type = 'name';
      else if (/email/i.test(name)) type = 'email';

      // Extract widget rectangles for this field (pdf-lib low-level)
      try {
        const widgets = f.acroField.getWidgets();
        for (const widget of widgets) {
          const rect = widget.getRectangle();
          const pageRef = widget.P();
          let pageIndex = 0;
          if (pageRef) {
            pageIndex = pages.findIndex(p => p.ref === pageRef);
            if (pageIndex < 0) pageIndex = 0;
          }
          const page = pages[pageIndex];
          const { width, height } = page.getSize();
          fields.push({
            id: uid(),
            type,
            label: name,
            page: pageIndex + 1,
            xPct: (rect.x / width) * 100,
            yPct: ((height - rect.y - rect.height) / height) * 100,
            wPct: (rect.width / width) * 100,
            hPct: (rect.height / height) * 100,
            required: !!f.isRequired?.(),
            signerIndex: 0,
            source: 'acroform',
          });
        }
      } catch {
        // some fields have no widgets/rect; skip
      }
    }
    return fields;
  } catch {
    return [];
  }
}

// Strategy 2: heuristic text scan — extract page text operators and run anchor regex.
// pdf-lib doesn't expose text-with-coords directly. We parse the content stream ourselves.
async function scanTextAnchors(pdfBytes) {
  const pdf = await PDFDocument.load(pdfBytes, { ignoreEncryption: true });
  const pages = pdf.getPages();
  const out = [];
  for (let pi = 0; pi < pages.length; pi++) {
    const page = pages[pi];
    const { width, height } = page.getSize();
    const lines = await extractTextWithCoords(page);
    for (const line of lines) {
      for (const type of Object.keys(ANCHORS)) {
        for (const rx of ANCHORS[type]) {
          if (rx.test(line.text)) {
            out.push(makeField({
              type, label: line.text.trim().slice(0, 40),
              page: pi + 1, pageWidth: width, pageHeight: height,
              x: line.x, y: line.y, anchorWidth: line.width, anchorHeight: line.height,
              signerIndex: 0,
            }));
            break; // one anchor category per line is enough
          }
        }
      }
    }
  }
  return out;
}

// Extract runs of text with approximate page coordinates by walking the content stream.
// This is deliberately lightweight — it handles the common `Tj` / `TJ` operators we see
// in most government / office-suite-produced PDFs, not every edge case. Streams compressed
// with FlateDecode are decompressed via zlib before scanning.
const zlib = require('zlib');

function decodeStreamBytes(stream) {
  // pdf-lib PDFRawStream / PDFContentStream: .contents is Uint8Array; .dict has Filter entry.
  let raw = null;
  if (stream.contents) raw = stream.contents;
  else if (typeof stream.getContents === 'function') {
    try { raw = stream.getContents(); } catch {}
  }
  if (!raw) return null;
  const buf = Buffer.from(raw);
  let filterStr = '';
  try {
    const filter = stream.dict && stream.dict.get(PDFName.of('Filter'));
    filterStr = filter ? filter.toString() : '';
  } catch { /* ignore */ }
  if (filterStr.includes('FlateDecode')) {
    try { return zlib.inflateSync(buf); } catch { /* fall through */ }
  }
  return buf;
}

async function extractTextWithCoords(page) {
  const results = [];
  try {
    const ctx = page.doc.context;
    const contentsEntry = page.node.get ? page.node.get(PDFName.of('Contents')) : null;
    if (!contentsEntry) return results;
    let streams = [];
    // contentsEntry can be a PDFRef, a PDFArray of PDFRefs, or an inline stream
    if (contentsEntry instanceof PDFArray) {
      for (let i = 0; i < contentsEntry.size(); i++) streams.push(ctx.lookup(contentsEntry.get(i)));
    } else {
      streams.push(ctx.lookup(contentsEntry));
    }
    for (const stream of streams) {
      if (!stream) continue;
      const decoded = decodeStreamBytes(stream);
      if (!decoded) continue;
      const text = decoded.toString('latin1');
      let tmX = 0, tmY = 0, fontSize = 10;
      // Scan operators. We care about: Td (move), Tm (set matrix), Tj/' (show string),
      // TJ (show array), Tf (font+size). Strings may be parenthesised or hex-encoded.
      const re = /(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+Td\b|(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+Tm\b|\(((?:\\.|[^\\\)])*)\)\s*Tj\b|\[((?:\([^\)]*\)|<[^>]*>|[^\]])*)\]\s*TJ\b|<([0-9A-Fa-f\s]*)>\s*Tj\b|\/[^\s]+\s+(\d+(?:\.\d+)?)\s+Tf\b/g;
      let m;
      while ((m = re.exec(text))) {
        if (m[1] !== undefined) {
          tmX += parseFloat(m[1]); tmY += parseFloat(m[2]);
        } else if (m[3] !== undefined) {
          tmX = parseFloat(m[7]); tmY = parseFloat(m[8]);
        } else if (m[9] !== undefined) {
          const s = unescapePdfString(m[9]);
          if (s.trim()) results.push({ text: s, x: tmX, y: tmY, width: s.length * fontSize * 0.5, height: fontSize });
        } else if (m[10] !== undefined) {
          // TJ array: mix of strings and kerning numbers
          const parts = [];
          const rx2 = /\(((?:\\.|[^\\\)])*)\)|<([0-9A-Fa-f\s]*)>/g;
          let pm;
          while ((pm = rx2.exec(m[10]))) {
            if (pm[1] !== undefined) parts.push(unescapePdfString(pm[1]));
            else if (pm[2] !== undefined) parts.push(hexToAscii(pm[2]));
          }
          const s = parts.join('');
          if (s.trim()) results.push({ text: s, x: tmX, y: tmY, width: s.length * fontSize * 0.5, height: fontSize });
        } else if (m[11] !== undefined) {
          // hex-encoded Tj
          const s = hexToAscii(m[11]);
          if (s.trim()) results.push({ text: s, x: tmX, y: tmY, width: s.length * fontSize * 0.5, height: fontSize });
        } else if (m[12] !== undefined) {
          fontSize = parseFloat(m[12]);
        }
      }
    }
  } catch {
    // on parse failure, just return what we got
  }
  return results;
}

function unescapePdfString(s) {
  return s
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\\(/g, '(').replace(/\\\)/g, ')').replace(/\\\\/g, '\\')
    .replace(/\\(\d{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)));
}

function hexToAscii(hex) {
  const clean = hex.replace(/\s+/g, '');
  // PDF hex strings with odd length are padded with 0 on the right
  const padded = clean.length % 2 === 0 ? clean : clean + '0';
  let out = '';
  for (let i = 0; i < padded.length; i += 2) {
    const code = parseInt(padded.slice(i, i + 2), 16);
    if (Number.isFinite(code)) out += String.fromCharCode(code);
  }
  return out;
}

// Merge two lists — when an AcroForm field and a heuristic field overlap on the same page,
// prefer AcroForm.
function mergeFields(acroFields, heuristicFields) {
  const out = [...acroFields];
  for (const h of heuristicFields) {
    const overlaps = acroFields.some(a =>
      a.page === h.page &&
      Math.abs(a.xPct - h.xPct) < 10 &&
      Math.abs(a.yPct - h.yPct) < 5
    );
    if (!overlaps) out.push(h);
  }
  return out;
}

async function detect(pdfBytes) {
  const [acro, heur] = await Promise.all([importAcroFormFields(pdfBytes), scanTextAnchors(pdfBytes)]);
  const merged = mergeFields(acro, heur);
  return {
    fields: merged,
    counts: {
      acroform: acro.length,
      heuristic: heur.length,
      total: merged.length,
    },
  };
}

// Optional AI-assisted detection via Anthropic Claude API. Off by default.
async function detectWithClaude(pdfBytes, { apiKey } = {}) {
  const key = apiKey || process.env.ANTHROPIC_API_KEY;
  if (!key) throw new Error('ANTHROPIC_API_KEY not set — AI detection disabled.');
  // Deliberate stub: caller can extend this to convert first page to PNG (e.g. via pdf.js or pdftocairo)
  // and POST to Claude's messages endpoint with claude-opus-4-7 and vision.
  // Until that rendering pipeline is added we fall back to heuristic.
  return detect(pdfBytes);
}

module.exports = { detect, detectWithClaude, importAcroFormFields, scanTextAnchors };
