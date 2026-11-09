// Server-side report generation services: DOCX (docx), PDF (pdfkit) and XLSX (exceljs).
// All three render the same ReportDoc structure produced by shared/report.ts.

import {
  AlignmentType, BorderStyle, Document, Footer, Header, HeadingLevel, ImageRun, Packer, Paragraph,
  ShadingType, Table, TableCell, TableRow, TextRun, WidthType,
} from 'docx';
import PDFDocument from 'pdfkit';
import ExcelJS from 'exceljs';
import type { Block, ReportDoc } from '../shared/report';

const NAVY = '16325C';
const TEAL = '0F8B8D';
const SAGE = 'DCE7DF';

export function pngSize(buf: Buffer): { w: number; h: number } | null {
  if (buf.length < 24 || buf.readUInt32BE(0) !== 0x89504e47) return null;
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}

function classificationLine(doc: ReportDoc) {
  return doc.isDemo ? 'DEMONSTRATION DATA — SYNTHETIC — NOT FOR CLIENT USE' : 'CONFIDENTIAL — Internal security assessment';
}

// ------------------------------------------------------------------ DOCX

export async function renderDocx(doc: ReportDoc, diagram?: Buffer): Promise<Buffer> {
  const children: (Paragraph | Table)[] = [];
  children.push(new Paragraph({ children: [new TextRun({ text: doc.title, bold: true, size: 48, color: NAVY })], spacing: { after: 120 } }));
  children.push(new Paragraph({ children: [new TextRun({ text: doc.subtitle, size: 28, color: TEAL })], spacing: { after: 240 } }));
  children.push(kvTable(doc.meta));
  children.push(new Paragraph({ children: [new TextRun({ text: `Generated ${doc.generatedAt.replace('T', ' ').slice(0, 16)} UTC`, italics: true, size: 18, color: '666666' })], spacing: { before: 120, after: 240 } }));

  for (const s of doc.sections) {
    children.push(new Paragraph({ text: s.heading, heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 120 } }));
    for (const b of s.blocks) children.push(...docxBlock(b, diagram));
  }

  const d = new Document({
    creator: 'Security Architecture Workbench',
    title: `${doc.title} — ${doc.subtitle}`,
    styles: {
      default: { document: { run: { font: 'Calibri', size: 20 } } },
      paragraphStyles: [{ id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', run: { size: 30, bold: true, color: NAVY } }],
    },
    sections: [{
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: classificationLine(doc), size: 16, color: doc.isDemo ? 'B5543C' : '666666', bold: doc.isDemo })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: `${doc.title} — ${doc.subtitle}`, size: 16, color: '666666' })] })] }) },
      children,
    }],
  });
  return Packer.toBuffer(d);
}

function cell(text: string, header = false) {
  return new TableCell({
    shading: header ? { type: ShadingType.CLEAR, color: 'auto', fill: NAVY } : undefined,
    children: [new Paragraph({ children: [new TextRun({ text, bold: header, color: header ? 'FFFFFF' : undefined, size: 17 })] })],
  });
}

function kvTable(rows: [string, string][]) {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: rows.map(([k, v]) => new TableRow({
      children: [
        new TableCell({ width: { size: 28, type: WidthType.PERCENTAGE }, shading: { type: ShadingType.CLEAR, color: 'auto', fill: SAGE }, children: [new Paragraph({ children: [new TextRun({ text: k, bold: true, size: 17 })] })] }),
        new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: v, size: 17 })] })] }),
      ],
    })),
  });
}

function docxBlock(b: Block, diagram?: Buffer): (Paragraph | Table)[] {
  switch (b.type) {
    case 'p':
      return [new Paragraph({ children: [new TextRun(b.text)], spacing: { after: 120 } })];
    case 'bullets':
      return b.items.map((i) => new Paragraph({ text: i, bullet: { level: 0 } }));
    case 'callout':
      return [new Paragraph({
        border: { left: { style: BorderStyle.SINGLE, size: 18, color: b.tone === 'warn' ? 'D08C3A' : TEAL, space: 8 } },
        shading: { type: ShadingType.CLEAR, color: 'auto', fill: b.tone === 'warn' ? 'FBF1E3' : 'E6F3F3' },
        children: [new TextRun({ text: b.text, size: 18 })], spacing: { before: 80, after: 160 },
      })];
    case 'kv':
      return [kvTable(b.rows), new Paragraph({ text: '' })];
    case 'table':
      if (!b.rows.length) return [new Paragraph({ children: [new TextRun({ text: 'No entries.', italics: true })] })];
      return [new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [new TableRow({ tableHeader: true, children: b.columns.map((c) => cell(c, true)) }), ...b.rows.map((r) => new TableRow({ children: r.map((c) => cell(c)) }))],
      }), new Paragraph({ text: '' })];
    case 'image': {
      const size = diagram && pngSize(diagram);
      if (!diagram || !size) return [new Paragraph({ children: [new TextRun({ text: '[Architecture diagram not supplied with export request]', italics: true })] })];
      const width = 600;
      const height = Math.round((size.h / size.w) * width);
      return [
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new ImageRun({ type: 'png', data: diagram, transformation: { width, height } })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: b.caption, italics: true, size: 16 })] }),
      ];
    }
  }
}

// ------------------------------------------------------------------ PDF

export function renderPdf(doc: ReportDoc, diagram?: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const pdf = new PDFDocument({ size: 'A4', margins: { top: 60, bottom: 60, left: 50, right: 50 }, bufferPages: true, info: { Title: `${doc.title} — ${doc.subtitle}`, Creator: 'Security Architecture Workbench' } });
    const chunks: Buffer[] = [];
    pdf.on('data', (c: Buffer) => chunks.push(c));
    pdf.on('end', () => resolve(Buffer.concat(chunks)));
    pdf.on('error', reject);
    const W = pdf.page.width - 100;

    pdf.fillColor('#' + NAVY).font('Helvetica-Bold').fontSize(24).text(doc.title);
    pdf.fillColor('#' + TEAL).font('Helvetica').fontSize(14).text(doc.subtitle).moveDown();
    pdfTable(pdf, ['Field', 'Value'], doc.meta, W, [0.3, 0.7]);
    pdf.fillColor('#666').fontSize(8).text(`Generated ${doc.generatedAt.replace('T', ' ').slice(0, 16)} UTC`).moveDown();

    for (const s of doc.sections) {
      ensure(pdf, 60);
      pdf.moveDown(0.6).fillColor('#' + NAVY).font('Helvetica-Bold').fontSize(15).text(s.heading).moveDown(0.3);
      for (const b of s.blocks) pdfBlock(pdf, b, W, diagram);
    }

    const range = pdf.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      pdf.switchToPage(i);
      const bottom = pdf.page.margins.bottom;
      pdf.page.margins.bottom = 0;
      pdf.font('Helvetica-Bold').fontSize(7).fillColor(doc.isDemo ? '#B5543C' : '#666').text(classificationLine(doc), 50, 30, { width: W, align: 'right' });
      pdf.font('Helvetica').fontSize(7).fillColor('#666').text(`Page ${i + 1} of ${range.count}`, 50, pdf.page.height - 40, { width: W, align: 'center' });
      pdf.page.margins.bottom = bottom;
    }
    pdf.end();
  });
}

function ensure(pdf: PDFKit.PDFDocument, h: number) {
  if (pdf.y + h > pdf.page.height - pdf.page.margins.bottom) pdf.addPage();
}

function pdfBlock(pdf: PDFKit.PDFDocument, b: Block, W: number, diagram?: Buffer) {
  pdf.font('Helvetica').fontSize(9.5).fillColor('#222');
  switch (b.type) {
    case 'p':
      pdf.text(b.text, { width: W }).moveDown(0.5);
      break;
    case 'bullets':
      for (const i of b.items) { ensure(pdf, 14); pdf.text(`•  ${i}`, { width: W, indent: 0 }); }
      pdf.moveDown(0.5);
      break;
    case 'callout': {
      const h = pdf.heightOfString(b.text, { width: W - 20 }) + 12;
      ensure(pdf, h);
      const y = pdf.y;
      pdf.rect(50, y, W, h).fill(b.tone === 'warn' ? '#FBF1E3' : '#E6F3F3');
      pdf.rect(50, y, 3, h).fill(b.tone === 'warn' ? '#D08C3A' : '#' + TEAL);
      pdf.fillColor('#222').text(b.text, 62, y + 6, { width: W - 20 });
      pdf.x = 50;
      pdf.y = y + h + 6;
      break;
    }
    case 'kv':
      pdfTable(pdf, ['Field', 'Value'], b.rows, W, [0.28, 0.72]);
      break;
    case 'table':
      if (!b.rows.length) pdf.font('Helvetica-Oblique').text('No entries.').moveDown(0.5);
      else pdfTable(pdf, b.columns, b.rows, W);
      break;
    case 'image':
      if (diagram && pngSize(diagram)) {
        const s = pngSize(diagram)!;
        const h = Math.min(420, (s.h / s.w) * W);
        ensure(pdf, h + 20);
        pdf.image(diagram, 50, pdf.y, { fit: [W, h], align: 'center' });
        pdf.y += h + 4;
        pdf.x = 50;
        pdf.font('Helvetica-Oblique').fontSize(8).text(b.caption, { width: W, align: 'center' }).moveDown(0.5);
      } else {
        pdf.font('Helvetica-Oblique').text('[Architecture diagram not supplied with export request]').moveDown(0.5);
      }
      break;
  }
}

function pdfTable(pdf: PDFKit.PDFDocument, columns: string[], rows: string[][], W: number, ratios?: number[]) {
  const widths = (ratios ?? columns.map(() => 1 / columns.length)).map((r) => r * W);
  const fs = columns.length > 6 ? 7 : 8;
  const pad = 3;
  const rowHeight = (cells: string[], font: string) => {
    pdf.font(font).fontSize(fs);
    return Math.max(...cells.map((c, i) => pdf.heightOfString(c || ' ', { width: widths[i] - pad * 2 }))) + pad * 2;
  };
  const drawRow = (cells: string[], header: boolean) => {
    const font = header ? 'Helvetica-Bold' : 'Helvetica';
    const h = rowHeight(cells, font);
    ensure(pdf, h);
    const y = pdf.y;
    let x = 50;
    cells.forEach((c, i) => {
      if (header) pdf.rect(x, y, widths[i], h).fill('#' + NAVY);
      else pdf.rect(x, y, widths[i], h).lineWidth(0.4).strokeColor('#C8D3CC').stroke();
      pdf.font(font).fontSize(fs).fillColor(header ? '#FFFFFF' : '#222').text(c || '', x + pad, y + pad, { width: widths[i] - pad * 2 });
      x += widths[i];
    });
    pdf.x = 50;
    pdf.y = y + h;
  };
  drawRow(columns, true);
  for (const r of rows) {
    const h = rowHeight(r, 'Helvetica');
    if (pdf.y + h > pdf.page.height - pdf.page.margins.bottom) { pdf.addPage(); drawRow(columns, true); }
    drawRow(r, false);
  }
  pdf.moveDown(0.6);
}

// ------------------------------------------------------------------ XLSX

export async function renderXlsx(doc: ReportDoc): Promise<Buffer> {
  const wb = new ExcelJS.Workbook();
  wb.creator = 'Security Architecture Workbench';
  wb.created = new Date(doc.generatedAt);
  const summary = wb.addWorksheet('Summary');
  summary.columns = [{ width: 34 }, { width: 100 }];
  summary.addRow([doc.title]).font = { bold: true, size: 16, color: { argb: 'FF' + NAVY } };
  summary.addRow([doc.subtitle]).font = { size: 12, color: { argb: 'FF' + TEAL } };
  summary.addRow([classificationLine(doc)]).font = { bold: true, color: { argb: doc.isDemo ? 'FFB5543C' : 'FF666666' } };
  summary.addRow([]);
  for (const [k, v] of doc.meta) summary.addRow([k, v]).getCell(1).font = { bold: true };
  summary.addRow([]);

  const used = new Set<string>(['Summary']);
  const sheetName = (base: string) => {
    let n = base.replace(/[\\/?*[\]:]/g, ' ').slice(0, 31) || 'Sheet';
    let i = 2;
    while (used.has(n)) n = `${base.slice(0, 27)} (${i++})`;
    used.add(n);
    return n;
  };

  for (const s of doc.sections) {
    for (const b of s.blocks) {
      if (b.type === 'kv') {
        summary.addRow([s.heading]).font = { bold: true, color: { argb: 'FF' + NAVY } };
        for (const [k, v] of b.rows) summary.addRow([k, v]);
        summary.addRow([]);
      } else if (b.type === 'p' && s.heading === 'Executive summary') {
        const r = summary.addRow(['Executive summary', b.text]);
        r.alignment = { wrapText: true, vertical: 'top' };
      } else if (b.type === 'table' && b.rows.length) {
        const ws = wb.addWorksheet(sheetName(b.sheet ?? s.heading));
        ws.addRow(b.columns);
        b.rows.forEach((r) => ws.addRow(r));
        const header = ws.getRow(1);
        header.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        header.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF' + NAVY } };
        ws.columns.forEach((col, i) => {
          const max = Math.max(b.columns[i].length, ...b.rows.map((r) => (r[i] ?? '').length));
          col.width = Math.min(60, Math.max(10, max + 2));
          col.alignment = { wrapText: true, vertical: 'top' };
        });
        ws.views = [{ state: 'frozen', ySplit: 1 }];
        ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: b.columns.length } };
      }
    }
  }
  return Buffer.from(await wb.xlsx.writeBuffer());
}
