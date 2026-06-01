//! Professional PDF rendering — agent 5.6.
//!
//! Uses `printpdf` with built-in fonts (Helvetica, Courier).
//! Text is encoded with WinAnsiEncoding: Latin-1 accented chars pass through
//! correctly; genuinely non-encodable code points (CJK, emoji) fall back to `?`.

use std::io::BufWriter;
use std::path::{Path, PathBuf};

use printpdf::{BuiltinFont, Mm, PdfDocument};

// ─── A4 portrait dimensions ───────────────────────────────────────────────────
const PAGE_WIDTH: f32 = 210.0;
const PAGE_HEIGHT: f32 = 297.0;

// Margins in mm
const MARGIN_LEFT: f32 = 20.0;
const MARGIN_RIGHT: f32 = 20.0;
const MARGIN_TOP: f32 = 20.0;
const MARGIN_BOTTOM: f32 = 15.0;

// Usable text width
const TEXT_WIDTH: f32 = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT;

// Font sizes (points)
const SIZE_TITLE: f32 = 22.0;
const SIZE_SUBTITLE: f32 = 14.0;
const SIZE_TIMESTAMP: f32 = 10.0;
const SIZE_LOGO: f32 = 18.0;
const SIZE_SECTION: f32 = 13.0;
const SIZE_BODY: f32 = 9.0;
const SIZE_FOOTER: f32 = 8.0;
const SIZE_MD_H1: f32 = 14.0; // markdown `#` heading inside a section
const SIZE_BULLET_INDENT: f32 = 4.0; // mm indent for bullet items

// Line height approximation: 1 pt ≈ 0.353 mm, leading 130%
fn line_height(size_pt: f32) -> f32 {
    size_pt * 0.353 * 1.3
}

/// Structured content for the PDF report.
#[derive(Debug, Clone)]
pub struct ContenuPdf {
    pub titre: String,
    pub sous_titre: String,
    pub resume_exec: String,
    pub inventaire: String,
    pub journal: String,
    pub mapping_conformite: String,
    pub plan_remediation: String,
    pub horodatage: String,
}

impl Default for ContenuPdf {
    fn default() -> Self {
        ContenuPdf {
            titre: "Compliance Report".to_string(),
            sous_titre: "MCP09 / MCP03 Monitoring".to_string(),
            resume_exec: String::new(),
            inventaire: String::new(),
            journal: String::new(),
            mapping_conformite: String::new(),
            plan_remediation: String::new(),
            horodatage: String::new(),
        }
    }
}

/// A logical line ready for rendering.
#[derive(Debug, Clone)]
enum LogicalLine {
    /// Regular body text, pre-wrapped.
    Body(String),
    /// Markdown H1 heading (rendered larger).
    Heading(String),
    /// Bullet item (rendered indented).
    Bullet(String),
    /// Table row (rendered monospace).
    TableRow(String),
    /// Blank spacer.
    Blank,
}

impl LogicalLine {
    fn size(&self) -> f32 {
        match self {
            LogicalLine::Heading(_) => SIZE_MD_H1,
            LogicalLine::TableRow(_) => SIZE_BODY - 0.5,
            _ => SIZE_BODY,
        }
    }
}

/// PDF rendering engine.
pub struct RenduPdf;

impl RenduPdf {
    /// Produce a default PDF at the given path.
    pub fn produire(chemin: &Path) -> anyhow::Result<()> {
        let contenu = ContenuPdf::default();
        RenduPdf::produire_contenu(&contenu, chemin)?;
        Ok(())
    }

    /// Produce a full PDF from the provided content.
    /// Returns the absolute path of the created file.
    pub fn produire_contenu(contenu: &ContenuPdf, chemin: &Path) -> anyhow::Result<PathBuf> {
        // Create A4 document
        let (doc, cover_page, cover_layer) = PdfDocument::new(
            "Sentinel MCP Compliance Report",
            Mm(PAGE_WIDTH),
            Mm(PAGE_HEIGHT),
            "Content",
        );

        // Fonts shared across all pages
        let font_title = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
        let font_normal = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

        // ── Cover page ─────────────────────────────────────────────────────────
        {
            let layer = doc.get_page(cover_page).get_layer(cover_layer);

            // Logo placeholder at top
            let y_logo = PAGE_HEIGHT - MARGIN_TOP - 10.0;
            layer.use_text(
                encode_winansi("[SENTINEL MCP]"),
                SIZE_LOGO,
                Mm(MARGIN_LEFT),
                Mm(y_logo),
                &font_title,
            );

            // Main title
            let y_title = y_logo - 20.0;
            for (i, line) in word_wrap(&encode_winansi(&contenu.titre), SIZE_TITLE, TEXT_WIDTH)
                .iter()
                .enumerate()
            {
                layer.use_text(
                    line.as_str(),
                    SIZE_TITLE,
                    Mm(MARGIN_LEFT),
                    Mm(y_title - i as f32 * line_height(SIZE_TITLE)),
                    &font_title,
                );
            }

            // Subtitle
            let y_sub = y_title - 2.0 * line_height(SIZE_TITLE) - 4.0;
            layer.use_text(
                encode_winansi(&contenu.sous_titre),
                SIZE_SUBTITLE,
                Mm(MARGIN_LEFT),
                Mm(y_sub),
                &font_normal,
            );

            // Timestamp
            let y_ts = y_sub - line_height(SIZE_SUBTITLE) - 6.0;
            layer.use_text(
                encode_winansi(&contenu.horodatage),
                SIZE_TIMESTAMP,
                Mm(MARGIN_LEFT),
                Mm(y_ts),
                &font_normal,
            );

            render_footer(&doc, cover_page, "Cover-Footer", &font_normal, 1)?;
        }

        // ── Report sections ────────────────────────────────────────────────────
        let sections: &[(&str, &str, bool)] = &[
            ("Executive summary", &contenu.resume_exec, false),
            ("Inventory", &contenu.inventaire, true),
            ("Changelog", &contenu.journal, true),
            ("Compliance mapping", &contenu.mapping_conformite, true),
            ("Remediation plan", &contenu.plan_remediation, false),
        ];

        let mut page_num = 2usize;
        for (section_title, text, monospace) in sections {
            // Parse text into logical lines with markdown and table awareness
            let logical_lines = parse_logical_lines(text, *monospace);

            // Available height on first section page (minus room for the heading)
            let y_start_heading = PAGE_HEIGHT - MARGIN_TOP;
            let y_start_body = y_start_heading - line_height(SIZE_SECTION) - 4.0;
            let usable_first = y_start_body - MARGIN_BOTTOM - line_height(SIZE_FOOTER) - 2.0;
            let usable_cont = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM - line_height(SIZE_FOOTER) - 2.0;

            // Paginate logical lines
            let pages = paginate(&logical_lines, usable_first, usable_cont);

            for (page_idx, block) in pages.iter().enumerate() {
                let layer_name = format!("Section-{}-p{}", section_title, page_idx + 1);
                let (page_ref, layer_ref) =
                    doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), &layer_name);
                let layer = doc.get_page(page_ref).get_layer(layer_ref);

                let mut y = PAGE_HEIGHT - MARGIN_TOP;

                // Section heading on first sub-page only
                if page_idx == 0 {
                    layer.use_text(
                        encode_winansi(section_title),
                        SIZE_SECTION,
                        Mm(MARGIN_LEFT),
                        Mm(y),
                        &font_bold,
                    );
                    y -= line_height(SIZE_SECTION) + 4.0;
                }

                // Render each logical line individually (no shared text section)
                for ll in block {
                    match ll {
                        LogicalLine::Blank => {
                            y -= line_height(SIZE_BODY) * 0.5;
                        }
                        LogicalLine::Heading(s) => {
                            layer.use_text(
                                encode_winansi(s),
                                SIZE_MD_H1,
                                Mm(MARGIN_LEFT),
                                Mm(y),
                                &font_bold,
                            );
                            y -= line_height(SIZE_MD_H1) + 1.0;
                        }
                        LogicalLine::Bullet(s) => {
                            let bullet_x = MARGIN_LEFT + SIZE_BULLET_INDENT;
                            // Draw the bullet glyph
                            layer.use_text(
                                encode_winansi("*"),
                                SIZE_BODY,
                                Mm(MARGIN_LEFT),
                                Mm(y),
                                &font_normal,
                            );
                            layer.use_text(
                                encode_winansi(s),
                                SIZE_BODY,
                                Mm(bullet_x),
                                Mm(y),
                                &font_normal,
                            );
                            y -= line_height(SIZE_BODY);
                        }
                        LogicalLine::TableRow(s) => {
                            layer.use_text(
                                encode_winansi(s),
                                SIZE_BODY - 0.5,
                                Mm(MARGIN_LEFT),
                                Mm(y),
                                &font_mono,
                            );
                            y -= line_height(SIZE_BODY - 0.5);
                        }
                        LogicalLine::Body(s) => {
                            let font = if *monospace { &font_mono } else { &font_normal };
                            layer.use_text(
                                encode_winansi(s),
                                SIZE_BODY,
                                Mm(MARGIN_LEFT),
                                Mm(y),
                                font,
                            );
                            y -= line_height(SIZE_BODY);
                        }
                    }
                }

                render_footer(
                    &doc,
                    page_ref,
                    &format!("Footer-{}", layer_name),
                    &font_normal,
                    page_num,
                )?;
                page_num += 1;
            }
        }

        // ── Save ───────────────────────────────────────────────────────────────
        let file = std::fs::File::create(chemin)?;
        doc.save(&mut BufWriter::new(file))?;

        Ok(chemin.to_path_buf())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Write the footer on the given page.
fn render_footer(
    doc: &printpdf::PdfDocumentReference,
    page: printpdf::PdfPageIndex,
    layer_name: &str,
    font: &printpdf::IndirectFontRef,
    number: usize,
) -> anyhow::Result<()> {
    let layer = doc.get_page(page).add_layer(layer_name);
    let text = format!(
        "Sentinel MCP · Signed with Ed25519 · Page {}",
        number
    );
    layer.use_text(
        encode_winansi(&text),
        SIZE_FOOTER,
        Mm(MARGIN_LEFT),
        Mm(MARGIN_BOTTOM - 5.0),
        font,
    );
    Ok(())
}

/// Encode a string to WinAnsiEncoding (Latin-1 superset).
///
/// - Pure ASCII graphic chars and space pass through unchanged.
/// - Accented Latin-1 chars (U+00A0..U+00FF) are preserved; `printpdf`
///   encodes them using their WinAnsi byte values (0xA0..0xFF).
/// - Typographic quotes and dashes are mapped to their ASCII equivalents.
/// - Everything else (CJK, emoji, surrogates …) falls back to `?`.
fn encode_winansi(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            let mapped = match c {
                // Newlines: skip (callers split on \n before calling encode_winansi)
                '\n' | '\r' => return vec![],
                // Printable ASCII + space/tab
                '\x20'..='\x7E' | '\t' => return vec![c],
                // WinAnsi Latin-1 supplement (U+00A0 – U+00FF) — passes through
                '\u{00A0}'..='\u{00FF}' => return vec![c],
                // Typographic punctuation → ASCII equivalents
                '\u{2018}' | '\u{2019}' => '\'',
                '\u{201C}' | '\u{201D}' => '"',
                '\u{2013}' | '\u{2014}' => '-',
                '\u{2026}' => '.',
                '\u{2022}' => '*',
                // Anything else: replacement
                _ => '?',
            };
            vec![mapped]
        })
        .collect()
}

/// Parse raw text into `LogicalLine`s, honouring `\n`, markdown headings,
/// bullets, pipe tables, and wrapping long lines.
fn parse_logical_lines(text: &str, monospace: bool) -> Vec<LogicalLine> {
    let mut result: Vec<LogicalLine> = Vec::new();

    for raw_line in text.split('\n') {
        // Trim trailing CR
        let raw_line = raw_line.trim_end_matches('\r');

        if raw_line.is_empty() {
            result.push(LogicalLine::Blank);
            continue;
        }

        // Markdown H1 heading
        if raw_line.starts_with("# ") {
            let heading_text = raw_line.trim_start_matches('#').trim().to_string();
            // Wrap heading if very long
            for wrapped in word_wrap(&heading_text, SIZE_MD_H1, TEXT_WIDTH) {
                result.push(LogicalLine::Heading(wrapped));
            }
            continue;
        }

        // Pipe table row — detect lines that contain `|`
        if raw_line.contains('|') {
            // Hard-wrap for mono font
            let chars_per_line = chars_per_line_mono(SIZE_BODY - 0.5, TEXT_WIDTH);
            let mut rest = raw_line;
            while rest.len() > chars_per_line {
                // Try to break at a safe char boundary
                let split_at = floor_char_boundary(rest, chars_per_line);
                result.push(LogicalLine::TableRow(rest[..split_at].to_string()));
                rest = &rest[split_at..];
            }
            result.push(LogicalLine::TableRow(rest.to_string()));
            continue;
        }

        // Bullet line
        if raw_line.starts_with("- ") || raw_line.starts_with("* ") {
            let item_text = raw_line[2..].to_string();
            let bullet_width = TEXT_WIDTH - SIZE_BULLET_INDENT;
            for wrapped in word_wrap(&item_text, SIZE_BODY, bullet_width) {
                result.push(LogicalLine::Bullet(wrapped));
            }
            continue;
        }

        // Regular body text
        if monospace {
            let chars_per = chars_per_line_mono(SIZE_BODY, TEXT_WIDTH);
            let mut rest = raw_line;
            while rest.len() > chars_per {
                let split_at = floor_char_boundary(rest, chars_per);
                result.push(LogicalLine::Body(rest[..split_at].to_string()));
                rest = &rest[split_at..];
            }
            result.push(LogicalLine::Body(rest.to_string()));
        } else {
            for wrapped in word_wrap(raw_line, SIZE_BODY, TEXT_WIDTH) {
                result.push(LogicalLine::Body(wrapped));
            }
        }
    }

    result
}

/// Number of characters per line for Courier (monospace).
/// Courier character width ≈ 0.6 × size_pt × 0.353 mm.
fn chars_per_line_mono(size_pt: f32, width_mm: f32) -> usize {
    ((width_mm / (size_pt * 0.353 * 0.6)).floor() as usize).max(20)
}

/// Find the largest byte index ≤ `pos` that lands on a UTF-8 char boundary.
fn floor_char_boundary(s: &str, pos: usize) -> usize {
    if pos >= s.len() {
        return s.len();
    }
    let mut p = pos;
    while p > 0 && !s.is_char_boundary(p) {
        p -= 1;
    }
    p
}

/// Wrap a single logical line of text to fit within `width_mm`.
/// Approximation: 1 char ≈ 0.55 × size_pt × 0.353 mm (proportional Helvetica).
fn word_wrap(text: &str, size_pt: f32, width_mm: f32) -> Vec<String> {
    let char_width = size_pt * 0.353 * 0.55;
    let max_chars = ((width_mm / char_width).floor() as usize).max(10);

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= max_chars {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

/// Distribute logical lines into page blocks.
fn paginate(
    lines: &[LogicalLine],
    first_page_height: f32,
    cont_page_height: f32,
) -> Vec<Vec<LogicalLine>> {
    let mut pages: Vec<Vec<LogicalLine>> = Vec::new();
    let mut current: Vec<LogicalLine> = Vec::new();
    let mut remaining = first_page_height;

    for ll in lines {
        let h = match ll {
            LogicalLine::Blank => line_height(SIZE_BODY) * 0.5,
            LogicalLine::Heading(_) => line_height(SIZE_MD_H1) + 1.0,
            _ => line_height(ll.size()),
        };

        if h > remaining && !current.is_empty() {
            pages.push(current.clone());
            current.clear();
            remaining = cont_page_height;
        }

        current.push(ll.clone());
        remaining -= h;
    }

    if !current.is_empty() || pages.is_empty() {
        pages.push(current);
    }
    pages
}
