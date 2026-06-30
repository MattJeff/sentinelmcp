//! Rendu PDF premium — agent 5.6.
//!
//! Moteur de mise en page bâti directement sur `printpdf` 0.7 (polices
//! intégrées Helvetica/Courier) : **aucune dépendance supplémentaire**, sortie
//! déterministe (compatible artefact signé Ed25519), 100 % local.
//!
//! Au lieu de poser du texte brut ligne par ligne, ce moteur dessine de vrais
//! éléments graphiques : page de garde avec cartes KPI et graphique de
//! sévérité, bandes de section colorées, et **tableaux** (en-tête à fond
//! coloré, zébrage, bordures, badges de sévérité). Le texte des sections est
//! parsé en blocs (titres, paragraphes, listes, tableaux pipe `| … |`) puis
//! mis en page avec pagination automatique (l'en-tête d'un tableau qui déborde
//! est répété en haut de la page suivante).
//!
//! Encodage WinAnsi : le Latin-1 accentué passe ; CJK/emoji → `?`.

use std::io::BufWriter;
use std::path::{Path, PathBuf};

use printpdf::path::{PaintMode, WindingOrder};
use printpdf::{
    BuiltinFont, Color, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference,
    PdfPageIndex, Point, Polygon, Rect, Rgb,
};

// ─── Géométrie A4 portrait (mm) ────────────────────────────────────────────────
const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const M_LEFT: f32 = 18.0;
const M_RIGHT: f32 = 18.0;
const M_TOP: f32 = 20.0;
const M_BOTTOM: f32 = 16.0;
const CONTENT_W: f32 = PAGE_W - M_LEFT - M_RIGHT;
/// Limite basse du contenu (au-dessus du pied de page).
const Y_FLOOR: f32 = M_BOTTOM + 6.0;

// ─── Palette (composantes 0.0–1.0) ─────────────────────────────────────────────
const C_INK: [f32; 3] = [0.11, 0.12, 0.16];
const C_MUTED: [f32; 3] = [0.43, 0.46, 0.53];
const C_ACCENT: [f32; 3] = [0.431, 0.337, 0.969]; // indigo
const C_BAND: [f32; 3] = [0.10, 0.12, 0.19]; // ardoise foncée (en-têtes)
const C_BORDER: [f32; 3] = [0.84, 0.86, 0.90];
const C_ZEBRA: [f32; 3] = [0.965, 0.972, 0.981];
const C_WHITE: [f32; 3] = [1.0, 1.0, 1.0];
const C_CARD_BG: [f32; 3] = [0.985, 0.988, 0.993];

// ─── Tailles de police (points) ────────────────────────────────────────────────
const S_COVER_TITLE: f32 = 24.0;
const S_COVER_SUB: f32 = 12.0;
const S_LOGO: f32 = 15.0;
const S_KPI_VALUE: f32 = 21.0;
const S_KPI_LABEL: f32 = 7.5;
const S_SECTION: f32 = 13.0;
const S_H1: f32 = 12.5;
const S_H2: f32 = 10.5;
const S_BODY: f32 = 9.0;
const S_TABLE: f32 = 8.3;
const S_TABLE_HEAD: f32 = 8.3;
const S_BADGE: f32 = 7.3;
const S_FOOTER: f32 = 7.5;

/// 1 pt ≈ 0.353 mm ; interligne 130 %.
fn lh(size_pt: f32) -> f32 {
    size_pt * 0.353 * 1.3
}

/// Largeur approchée d'un texte Helvetica (mm) : largeur moyenne ≈ 0.5 × taille.
fn larg_txt(s: &str, size_pt: f32) -> f32 {
    s.chars().count() as f32 * size_pt * 0.353 * 0.5
}

// ════════════════════════════════════════════════════════════════════════════
//  Modèle de contenu
// ════════════════════════════════════════════════════════════════════════════

/// Une carte KPI de la page de garde.
#[derive(Debug, Clone)]
pub struct KpiPdf {
    pub label: String,
    pub valeur: String,
    /// Couleur d'accent du liseré supérieur.
    pub accent: [f32; 3],
}

/// Une barre du graphique « findings par sévérité ».
#[derive(Debug, Clone)]
pub struct BarreSeverite {
    pub label: String,
    pub valeur: u32,
    pub couleur: [f32; 3],
}

/// Contenu structuré du rapport PDF.
#[derive(Debug, Clone)]
pub struct ContenuPdf {
    pub titre: String,
    pub sous_titre: String,
    /// Période analysée, ex. « 2026-06-01 → 2026-06-30 » (vide = masqué).
    pub periode: String,
    /// Cartes KPI de la page de garde (vide = masqué).
    pub kpis: Vec<KpiPdf>,
    /// Barres du graphique de sévérité (vide = masqué).
    pub graphique_severite: Vec<BarreSeverite>,
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
            periode: String::new(),
            kpis: Vec::new(),
            graphique_severite: Vec::new(),
            resume_exec: String::new(),
            inventaire: String::new(),
            journal: String::new(),
            mapping_conformite: String::new(),
            plan_remediation: String::new(),
            horodatage: String::new(),
        }
    }
}

/// Bloc logique issu du parsing d'une section markdown.
#[derive(Debug, Clone)]
enum Bloc {
    /// Titre (`#` niveau 1, `##`+ niveau 2).
    Titre { texte: String, niveau: u8 },
    /// Paragraphe (pré-enveloppé en lignes).
    Para(Vec<String>),
    /// Élément de liste (pré-enveloppé).
    Puce(Vec<String>),
    /// Encart « > … » (callout).
    Callout(Vec<String>),
    /// Tableau pipe.
    Tableau(Tableau),
    /// Espace vertical.
    Espace,
}

#[derive(Debug, Clone)]
struct Tableau {
    entetes: Vec<String>,
    lignes: Vec<Vec<String>>,
}

// ════════════════════════════════════════════════════════════════════════════
//  Moteur de rendu
// ════════════════════════════════════════════════════════════════════════════

/// Polices partagées par tout le document.
struct Polices {
    bold: IndirectFontRef,
    normal: IndirectFontRef,
}

/// Curseur de mise en page : page courante + ordonnée + numéro.
struct Pager<'a> {
    doc: &'a PdfDocumentReference,
    fonts: &'a Polices,
    page: PdfPageIndex,
    layer: PdfLayerReference,
    /// Ordonnée du haut de la prochaine zone à dessiner (mm depuis le bas).
    y: f32,
    page_num: usize,
}

impl<'a> Pager<'a> {
    fn layer(&self) -> PdfLayerReference {
        self.doc.get_page(self.page).get_layer(self.layer.layer.clone())
    }

    /// Ouvre une nouvelle page de contenu (avec pied de page) et place le
    /// curseur en haut de la zone utile.
    fn nouvelle_page(&mut self) {
        let (p, l) = self.doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Content");
        self.page = p;
        self.layer = self.doc.get_page(p).get_layer(l);
        self.page_num += 1;
        self.y = PAGE_H - M_TOP;
        pied_de_page(&self.layer(), self.fonts, self.page_num);
    }

    /// Garantit `h` mm d'espace ; saute à une nouvelle page si besoin.
    /// Retourne `true` si un saut de page a eu lieu.
    fn assurer(&mut self, h: f32) -> bool {
        if self.y - h < Y_FLOOR {
            self.nouvelle_page();
            true
        } else {
            false
        }
    }
}

/// Moteur de rendu PDF.
pub struct RenduPdf;

impl RenduPdf {
    /// Produit un PDF par défaut au chemin donné.
    pub fn produire(chemin: &Path) -> anyhow::Result<()> {
        RenduPdf::produire_contenu(&ContenuPdf::default(), chemin)?;
        Ok(())
    }

    /// Produit le PDF complet ; retourne le chemin absolu du fichier créé.
    pub fn produire_contenu(contenu: &ContenuPdf, chemin: &Path) -> anyhow::Result<PathBuf> {
        let (doc, cover_page, cover_layer) =
            PdfDocument::new("Sentinel MCP Compliance Report", Mm(PAGE_W), Mm(PAGE_H), "Cover");

        let fonts = Polices {
            bold: doc.add_builtin_font(BuiltinFont::HelveticaBold)?,
            normal: doc.add_builtin_font(BuiltinFont::Helvetica)?,
        };

        // ── Page de garde ───────────────────────────────────────────────────
        let cover = doc.get_page(cover_page).get_layer(cover_layer);
        dessiner_garde(&cover, &fonts, contenu);
        pied_de_page(&cover, &fonts, 1);

        // ── Sections ────────────────────────────────────────────────────────
        let mut pager = Pager {
            doc: &doc,
            fonts: &fonts,
            page: cover_page,
            layer: cover,
            y: 0.0,
            page_num: 1,
        };

        let sections: &[(&str, &str, bool)] = &[
            ("Executive summary", &contenu.resume_exec, false),
            ("Inventory", &contenu.inventaire, true),
            ("Change log", &contenu.journal, true),
            ("Compliance mapping", &contenu.mapping_conformite, false),
            ("Remediation plan", &contenu.plan_remediation, false),
        ];

        for (titre, texte, _mono) in sections {
            pager.nouvelle_page();
            bande_section(&pager.layer(), &fonts, titre, pager.y);
            pager.y -= 14.0;

            let blocs = parser_blocs(texte);
            for bloc in &blocs {
                dessiner_bloc(&mut pager, bloc);
            }
        }

        let file = std::fs::File::create(chemin)?;
        doc.save(&mut BufWriter::new(file))?;
        Ok(chemin.to_path_buf())
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Primitives de dessin
// ════════════════════════════════════════════════════════════════════════════

fn rgb(c: [f32; 3]) -> Color {
    Color::Rgb(Rgb::new(c[0], c[1], c[2], None))
}

/// Texte (peint avec la couleur de remplissage courante → on la fixe à chaque fois).
fn texte(l: &PdfLayerReference, s: &str, size: f32, x: f32, y: f32, font: &IndirectFontRef, c: [f32; 3]) {
    l.set_fill_color(rgb(c));
    l.use_text(encode_winansi(s), size, Mm(x), Mm(y), font);
}

/// Rectangle plein dont le bord supérieur est à `y_haut`.
fn rect_plein(l: &PdfLayerReference, x: f32, y_haut: f32, w: f32, h: f32, c: [f32; 3]) {
    l.set_fill_color(rgb(c));
    l.add_rect(Rect::new(Mm(x), Mm(y_haut - h), Mm(x + w), Mm(y_haut)).with_mode(PaintMode::Fill));
}

/// Rectangle au contour seul.
fn rect_borde(l: &PdfLayerReference, x: f32, y_haut: f32, w: f32, h: f32, c: [f32; 3], ep: f32) {
    l.set_outline_color(rgb(c));
    l.set_outline_thickness(ep);
    l.add_rect(Rect::new(Mm(x), Mm(y_haut - h), Mm(x + w), Mm(y_haut)).with_mode(PaintMode::Stroke));
}

/// Trait horizontal.
fn trait_h(l: &PdfLayerReference, x1: f32, x2: f32, y: f32, c: [f32; 3], ep: f32) {
    l.set_outline_color(rgb(c));
    l.set_outline_thickness(ep);
    let ligne = printpdf::Line {
        points: vec![(Point::new(Mm(x1), Mm(y)), false), (Point::new(Mm(x2), Mm(y)), false)],
        is_closed: false,
    };
    l.add_line(ligne);
}

/// Petit écusson plein (logo), pointe en bas, centré sur (cx, cy_haut).
fn ecusson(l: &PdfLayerReference, cx: f32, y_haut: f32, w: f32, h: f32, c: [f32; 3]) {
    let demi = w / 2.0;
    let epaule = h * 0.62;
    let pts = vec![
        (Point::new(Mm(cx - demi), Mm(y_haut)), false),
        (Point::new(Mm(cx + demi), Mm(y_haut)), false),
        (Point::new(Mm(cx + demi), Mm(y_haut - epaule)), false),
        (Point::new(Mm(cx), Mm(y_haut - h)), false),
        (Point::new(Mm(cx - demi), Mm(y_haut - epaule)), false),
    ];
    l.set_fill_color(rgb(c));
    l.add_polygon(Polygon {
        rings: vec![pts],
        mode: PaintMode::Fill,
        winding_order: WindingOrder::NonZero,
    });
}

/// Texte centré verticalement dans une bande [y_haut-h, y_haut].
fn texte_centre_v(l: &PdfLayerReference, s: &str, size: f32, x: f32, y_haut: f32, h: f32, font: &IndirectFontRef, c: [f32; 3]) {
    let baseline = y_haut - h + (h - size * 0.353 * 0.72) / 2.0;
    texte(l, s, size, x, baseline, font, c);
}

// ════════════════════════════════════════════════════════════════════════════
//  Page de garde
// ════════════════════════════════════════════════════════════════════════════

fn dessiner_garde(l: &PdfLayerReference, f: &Polices, c: &ContenuPdf) {
    // Bandeau supérieur pleine largeur.
    let band_h = 42.0;
    rect_plein(l, 0.0, PAGE_H, PAGE_W, band_h, C_BAND);
    // Liseré d'accent sous le bandeau.
    rect_plein(l, 0.0, PAGE_H - band_h, PAGE_W, 1.4, C_ACCENT);

    // Logo écusson + wordmark.
    let logo_cx = M_LEFT + 4.0;
    let logo_top = PAGE_H - 12.0;
    ecusson(l, logo_cx, logo_top, 8.0, 10.0, C_ACCENT);
    ecusson(l, logo_cx, logo_top - 2.2, 4.0, 5.0, C_WHITE);
    texte(l, "SENTINEL MCP", S_LOGO, logo_cx + 8.0, logo_top - 7.0, &f.bold, C_WHITE);
    texte(l, "Local-first MCP detection & response", 8.0, logo_cx + 8.0, logo_top - 12.0, &f.normal, [0.72, 0.75, 0.85]);

    // Titre principal.
    let mut y = PAGE_H - band_h - 18.0;
    for line in word_wrap(&c.titre, S_COVER_TITLE, CONTENT_W) {
        texte(l, &line, S_COVER_TITLE, M_LEFT, y, &f.bold, C_INK);
        y -= lh(S_COVER_TITLE);
    }
    y -= 1.0;
    if !c.sous_titre.is_empty() {
        texte(l, &c.sous_titre, S_COVER_SUB, M_LEFT, y, &f.normal, C_MUTED);
        y -= lh(S_COVER_SUB);
    }
    if !c.periode.is_empty() {
        texte(l, &format!("Analysis period: {}", c.periode), 9.5, M_LEFT, y, &f.normal, C_MUTED);
        y -= lh(9.5);
    }

    // Cartes KPI.
    y -= 6.0;
    if !c.kpis.is_empty() {
        let n = c.kpis.len().min(4);
        let gap = 5.0;
        let card_w = (CONTENT_W - gap * (n as f32 - 1.0)) / n as f32;
        let card_h = 27.0;
        let card_top = y;
        for (i, kpi) in c.kpis.iter().take(4).enumerate() {
            let x = M_LEFT + i as f32 * (card_w + gap);
            rect_plein(l, x, card_top, card_w, card_h, C_CARD_BG);
            rect_borde(l, x, card_top, card_w, card_h, C_BORDER, 0.4);
            rect_plein(l, x, card_top, card_w, 2.2, kpi.accent); // liseré accent
            texte(l, &kpi.label.to_uppercase(), S_KPI_LABEL, x + 4.0, card_top - 8.5, &f.bold, C_MUTED);
            texte(l, &kpi.valeur, S_KPI_VALUE, x + 4.0, card_top - 21.0, &f.bold, C_INK);
        }
        y = card_top - card_h - 12.0;
    }

    // Graphique de sévérité (barres horizontales).
    if !c.graphique_severite.is_empty() {
        texte(l, "Findings by severity", S_H2, M_LEFT, y, &f.bold, C_INK);
        y -= 8.0;
        let max = c.graphique_severite.iter().map(|b| b.valeur).max().unwrap_or(1).max(1) as f32;
        let label_w = 26.0;
        let bar_max = CONTENT_W - label_w - 16.0;
        let row_h = 9.0;
        for b in &c.graphique_severite {
            let bar_top = y;
            texte_centre_v(l, &b.label, S_BODY, M_LEFT, bar_top, row_h, &f.normal, C_INK);
            // rail
            rect_plein(l, M_LEFT + label_w, bar_top - 1.5, bar_max, row_h - 3.0, [0.93, 0.94, 0.96]);
            // barre
            let w = (b.valeur as f32 / max) * bar_max;
            if w > 0.3 {
                rect_plein(l, M_LEFT + label_w, bar_top - 1.5, w, row_h - 3.0, b.couleur);
            }
            texte_centre_v(l, &b.valeur.to_string(), S_BODY, M_LEFT + label_w + bar_max + 3.0, bar_top, row_h, &f.bold, C_MUTED);
            y -= row_h;
        }
    }

    // Horodatage en bas de garde.
    if !c.horodatage.is_empty() {
        texte(l, &format!("Generated on {}", c.horodatage), 8.0, M_LEFT, M_BOTTOM + 12.0, &f.normal, C_MUTED);
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Bande de section & pied de page
// ════════════════════════════════════════════════════════════════════════════

fn bande_section(l: &PdfLayerReference, f: &Polices, titre: &str, y_haut: f32) {
    let h = 10.0;
    // Bloc d'accent à gauche + titre.
    rect_plein(l, M_LEFT, y_haut, 3.0, h, C_ACCENT);
    texte_centre_v(l, titre, S_SECTION, M_LEFT + 6.0, y_haut, h, &f.bold, C_INK);
    trait_h(l, M_LEFT, M_LEFT + CONTENT_W, y_haut - h - 1.5, C_BORDER, 0.5);
}

fn pied_de_page(l: &PdfLayerReference, f: &Polices, num: usize) {
    let y = M_BOTTOM;
    trait_h(l, M_LEFT, M_LEFT + CONTENT_W, y + 3.5, C_BORDER, 0.4);
    texte(l, "Sentinel MCP · Signed with Ed25519", S_FOOTER, M_LEFT, y - 1.0, &f.normal, C_MUTED);
    let p = format!("Page {}", num);
    let w = larg_txt(&p, S_FOOTER);
    texte(l, &p, S_FOOTER, M_LEFT + CONTENT_W - w, y - 1.0, &f.normal, C_MUTED);
}

// ════════════════════════════════════════════════════════════════════════════
//  Rendu des blocs
// ════════════════════════════════════════════════════════════════════════════

fn dessiner_bloc(p: &mut Pager, bloc: &Bloc) {
    match bloc {
        Bloc::Espace => {
            p.y -= lh(S_BODY) * 0.5;
        }
        Bloc::Titre { texte: t, niveau } => {
            let size = if *niveau <= 1 { S_H1 } else { S_H2 };
            p.assurer(lh(size) + 3.0);
            p.y -= 2.0;
            texte(&p.layer(), t, size, M_LEFT, p.y - size * 0.353, &p.fonts.bold, C_INK);
            p.y -= lh(size) + 1.5;
        }
        Bloc::Para(lignes) => {
            for ln in lignes {
                p.assurer(lh(S_BODY));
                texte(&p.layer(), ln, S_BODY, M_LEFT, p.y - S_BODY * 0.353, &p.fonts.normal, C_INK);
                p.y -= lh(S_BODY);
            }
        }
        Bloc::Puce(lignes) => {
            for (i, ln) in lignes.iter().enumerate() {
                p.assurer(lh(S_BODY));
                if i == 0 {
                    rect_plein(&p.layer(), M_LEFT + 1.0, p.y - 1.4, 1.4, 1.4, C_ACCENT);
                }
                texte(&p.layer(), ln, S_BODY, M_LEFT + 5.0, p.y - S_BODY * 0.353, &p.fonts.normal, C_INK);
                p.y -= lh(S_BODY);
            }
        }
        Bloc::Callout(lignes) => {
            let h = lignes.len() as f32 * lh(S_BODY) + 3.0;
            p.assurer(h + 2.0);
            let top = p.y;
            rect_plein(&p.layer(), M_LEFT, top, CONTENT_W, h, [0.96, 0.97, 1.0]);
            rect_plein(&p.layer(), M_LEFT, top, 2.2, h, C_ACCENT);
            let mut yy = top - 2.5;
            for ln in lignes {
                texte(&p.layer(), ln, S_BODY, M_LEFT + 6.0, yy - S_BODY * 0.353, &p.fonts.normal, C_INK);
                yy -= lh(S_BODY);
            }
            p.y -= h + 2.0;
        }
        Bloc::Tableau(t) => dessiner_tableau(p, t),
    }
}

fn dessiner_tableau(p: &mut Pager, t: &Tableau) {
    let ncol = t.entetes.len().max(1);
    let largeurs = largeurs_colonnes(t, ncol);
    let row_h = 7.2;
    let pad = 2.0;

    p.y -= 1.0;
    // En-tête (répété en cas de saut de page).
    let dessiner_entete = |p: &mut Pager| {
        p.assurer(row_h);
        let top = p.y;
        let l = p.layer();
        rect_plein(&l, M_LEFT, top, CONTENT_W, row_h, C_BAND);
        let mut x = M_LEFT;
        for (i, h) in t.entetes.iter().enumerate() {
            let cw = largeurs[i];
            let s = tronquer(h, S_TABLE_HEAD, cw - pad * 2.0);
            texte_centre_v(&l, &s, S_TABLE_HEAD, x + pad, top, row_h, &p.fonts.bold, C_WHITE);
            x += cw;
        }
        p.y -= row_h;
    };
    dessiner_entete(p);

    for (ri, ligne) in t.lignes.iter().enumerate() {
        // Saut de page → re-dessiner l'en-tête en haut de la nouvelle page.
        if p.assurer(row_h) {
            dessiner_entete(p);
        }
        let top = p.y;
        let l = p.layer();
        if ri % 2 == 1 {
            rect_plein(&l, M_LEFT, top, CONTENT_W, row_h, C_ZEBRA);
        }
        let mut x = M_LEFT;
        for (ci, cw) in largeurs.iter().enumerate() {
            let cell = ligne.get(ci).map(String::as_str).unwrap_or("");
            if let Some(coul) = couleur_severite(cell) {
                badge(&l, cell, x + pad, top, row_h, coul, p.fonts);
            } else {
                let s = tronquer(cell, S_TABLE, cw - pad * 2.0);
                texte_centre_v(&l, &s, S_TABLE, x + pad, top, row_h, &p.fonts.normal, C_INK);
            }
            x += cw;
        }
        trait_h(&l, M_LEFT, M_LEFT + CONTENT_W, top - row_h, C_BORDER, 0.3);
        p.y -= row_h;
    }
    p.y -= 3.0;
}

/// Badge de sévérité : pastille pleine colorée + texte blanc.
fn badge(l: &PdfLayerReference, label: &str, x: f32, y_haut: f32, row_h: f32, coul: [f32; 3], f: &Polices) {
    let txt = label.trim();
    // Largeur estimée avec une marge confortable (le gras est plus large que
    // l'estimation moyenne) pour que le libellé ne déborde jamais de la pastille.
    let bw = (txt.chars().count() as f32 * S_BADGE * 0.353 * 0.62 + 4.0).min(30.0);
    let bh = 4.6;
    let by = y_haut - (row_h - bh) / 2.0;
    rect_plein(l, x, by, bw, bh, coul);
    texte_centre_v(l, txt, S_BADGE, x + 2.0, by, bh, &f.bold, C_WHITE);
}

/// Couleur d'un libellé de sévérité / couleur de serveur, sinon `None`.
fn couleur_severite(s: &str) -> Option<[f32; 3]> {
    match s.trim().to_lowercase().as_str() {
        "critique" | "critical" | "rouge" | "red" => Some([0.84, 0.19, 0.25]),
        "haute" | "high" | "élevée" | "elevee" => Some([0.90, 0.45, 0.12]),
        "moyenne" | "medium" | "orange" => Some([0.92, 0.66, 0.13]),
        "info" | "basse" | "low" => Some([0.36, 0.46, 0.62]),
        "vert" | "green" | "ok" => Some([0.13, 0.62, 0.40]),
        _ => None,
    }
}

/// Largeurs de colonnes (mm) proportionnelles au contenu, somme = CONTENT_W.
fn largeurs_colonnes(t: &Tableau, ncol: usize) -> Vec<f32> {
    let mut poids = vec![1.0_f32; ncol];
    for ci in 0..ncol {
        let mut maxc = t.entetes.get(ci).map(|s| s.chars().count()).unwrap_or(3);
        for ligne in &t.lignes {
            if let Some(cell) = ligne.get(ci) {
                maxc = maxc.max(cell.chars().count().min(48));
            }
        }
        poids[ci] = (maxc as f32).max(4.0);
    }
    let somme: f32 = poids.iter().sum();
    let min_w = 17.0_f32.min(CONTENT_W / ncol as f32);
    let mut w: Vec<f32> = poids.iter().map(|p| (p / somme) * CONTENT_W).collect();
    // Plancher par colonne, puis renormalisation pour conserver la largeur totale.
    for x in w.iter_mut() {
        *x = x.max(min_w);
    }
    let s2: f32 = w.iter().sum();
    for x in w.iter_mut() {
        *x *= CONTENT_W / s2;
    }
    w
}

/// Tronque `s` pour tenir dans `w` mm à la taille donnée, avec « … ».
fn tronquer(s: &str, size: f32, w: f32) -> String {
    let s = s.trim();
    if larg_txt(s, size) <= w {
        return s.to_string();
    }
    let max_chars = ((w / (size * 0.353 * 0.5)).floor() as usize).saturating_sub(1).max(1);
    let mut out: String = s.chars().take(max_chars).collect();
    out.push('…');
    out
}

// ════════════════════════════════════════════════════════════════════════════
//  Parsing markdown → blocs
// ════════════════════════════════════════════════════════════════════════════

fn parser_blocs(texte: &str) -> Vec<Bloc> {
    let mut blocs = Vec::new();
    let lignes: Vec<&str> = texte.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let mut i = 0;
    while i < lignes.len() {
        let ligne = lignes[i];
        let nettoye = nettoyer_inline(ligne);

        if ligne.trim().is_empty() {
            blocs.push(Bloc::Espace);
            i += 1;
            continue;
        }

        // Titre markdown.
        if let Some(rest) = ligne.trim_start().strip_prefix('#') {
            let niveau = if rest.starts_with('#') { 2 } else { 1 };
            let t = ligne.trim_start_matches('#').trim();
            blocs.push(Bloc::Titre { texte: nettoyer_inline(t), niveau });
            i += 1;
            continue;
        }

        // Tableau pipe : regrouper les lignes consécutives contenant « | ».
        if ligne.contains('|') {
            let mut rows: Vec<Vec<String>> = Vec::new();
            while i < lignes.len() && lignes[i].contains('|') {
                let cells = decouper_cellules(lignes[i]);
                // Ignorer la ligne de séparation « |---|---| ».
                let est_sep = cells.iter().all(|c| {
                    let t = c.trim();
                    !t.is_empty() && t.chars().all(|ch| ch == '-' || ch == ':')
                });
                if !est_sep && !cells.is_empty() {
                    rows.push(cells);
                }
                i += 1;
            }
            if !rows.is_empty() {
                let entetes = rows.remove(0);
                blocs.push(Bloc::Tableau(Tableau { entetes, lignes: rows }));
            }
            continue;
        }

        // Callout « > … ».
        if let Some(rest) = ligne.trim_start().strip_prefix('>') {
            let contenu = word_wrap(&nettoyer_inline(rest.trim()), S_BODY, CONTENT_W - 8.0);
            blocs.push(Bloc::Callout(contenu));
            i += 1;
            continue;
        }

        // Puce.
        let t = ligne.trim_start();
        if let Some(rest) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")) {
            let contenu = word_wrap(&nettoyer_inline(rest), S_BODY, CONTENT_W - 5.0);
            blocs.push(Bloc::Puce(contenu));
            i += 1;
            continue;
        }

        // Paragraphe.
        blocs.push(Bloc::Para(word_wrap(&nettoye, S_BODY, CONTENT_W)));
        i += 1;
    }
    blocs
}

/// Découpe une ligne de tableau pipe en cellules (sans les `|` de bord).
fn decouper_cellules(ligne: &str) -> Vec<String> {
    let t = ligne.trim();
    let t = t.strip_prefix('|').unwrap_or(t);
    let t = t.strip_suffix('|').unwrap_or(t);
    t.split('|').map(|c| nettoyer_inline(c.trim())).collect()
}

/// Retire les marqueurs markdown inline (`**`, `` ` ``, `_`).
fn nettoyer_inline(s: &str) -> String {
    s.replace("**", "").replace('`', "").replace('_', " ")
}

// ════════════════════════════════════════════════════════════════════════════
//  Helpers texte (encodage, wrapping)
// ════════════════════════════════════════════════════════════════════════════

/// Encode en WinAnsi (Latin-1) ; remplace les non-encodables par `?`.
fn encode_winansi(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            let mapped = match c {
                '\n' | '\r' => return Vec::new(),
                '\x20'..='\x7E' | '\t' => return vec![c],
                '\u{00A0}'..='\u{00FF}' => return vec![c],
                '\u{2018}' | '\u{2019}' => '\'',
                '\u{201C}' | '\u{201D}' => '"',
                '\u{2013}' | '\u{2014}' => '-',
                '\u{2026}' => '.',
                '\u{2022}' => '*',
                '\u{2192}' => '>', // flèche → (période)
                _ => '?',
            };
            vec![mapped]
        })
        .collect()
}

/// Enveloppe un texte pour tenir dans `width_mm` (Helvetica proportionnel).
fn word_wrap(text: &str, size_pt: f32, width_mm: f32) -> Vec<String> {
    let char_width = size_pt * 0.353 * 0.52;
    let max_chars = ((width_mm / char_width).floor() as usize).max(10);

    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= max_chars {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn contenu_demo() -> ContenuPdf {
        ContenuPdf {
            titre: "Compliance Report — Sentinel MCP".to_string(),
            sous_titre: "Evidence bundle MCP09 / MCP03".to_string(),
            periode: "2026-06-01 → 2026-06-30".to_string(),
            kpis: vec![
                KpiPdf { label: "Servers".into(), valeur: "9".into(), accent: C_ACCENT },
                KpiPdf { label: "At risk".into(), valeur: "2".into(), accent: [0.90, 0.45, 0.12] },
                KpiPdf { label: "Critical".into(), valeur: "0".into(), accent: [0.84, 0.19, 0.25] },
                KpiPdf { label: "Open".into(), valeur: "12".into(), accent: [0.36, 0.46, 0.62] },
            ],
            graphique_severite: vec![
                BarreSeverite { label: "Critical".into(), valeur: 0, couleur: [0.84, 0.19, 0.25] },
                BarreSeverite { label: "High".into(), valeur: 12, couleur: [0.90, 0.45, 0.12] },
                BarreSeverite { label: "Medium".into(), valeur: 3, couleur: [0.92, 0.66, 0.13] },
            ],
            resume_exec: "# Executive summary\n\nSummary text.\n\n> WARNING: 2 servers to review.\n".to_string(),
            inventaire: "| ID | Endpoint | Color |\n|---|---|---|\n| abc | npx server | Red |\n| def | npx other | Green |\n".to_string(),
            journal: "| Date | Severity | Title |\n|---|---|---|\n| 2026-06-30 | High | YARA rule |\n".to_string(),
            mapping_conformite: "# Mapping\n\n| Finding | Framework | ID |\n|---|---|---|\n| YARA rule | OWASP | MCP03 |\n".to_string(),
            plan_remediation: "# Plan\n\n- First action\n- Second action\n".to_string(),
            horodatage: "2026-06-30T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn produit_un_pdf_non_vide() {
        let tmp = std::env::temp_dir().join(format!("sentinel-test-{}.pdf", uuid_simple()));
        let p = RenduPdf::produire_contenu(&contenu_demo(), &tmp).expect("rendu PDF");
        let meta = std::fs::metadata(&p).expect("fichier créé");
        assert!(meta.len() > 1500, "le PDF doit contenir du contenu (taille {} octets)", meta.len());
        // En-tête PDF valide.
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(&bytes[..5], b"%PDF-", "en-tête PDF valide");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn parser_detecte_tableau_titre_callout_puce() {
        let blocs = parser_blocs("# Titre\n\nPara.\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n> note\n\n- item\n");
        assert!(matches!(blocs[0], Bloc::Titre { niveau: 1, .. }));
        assert!(blocs.iter().any(|b| matches!(b, Bloc::Tableau(_))));
        assert!(blocs.iter().any(|b| matches!(b, Bloc::Callout(_))));
        assert!(blocs.iter().any(|b| matches!(b, Bloc::Puce(_))));
        // Le tableau a 2 entêtes et 1 ligne (la ligne « |---| » est ignorée).
        if let Some(Bloc::Tableau(t)) = blocs.iter().find(|b| matches!(b, Bloc::Tableau(_))) {
            assert_eq!(t.entetes.len(), 2);
            assert_eq!(t.lignes.len(), 1);
        }
    }

    #[test]
    fn badge_detecte_severites_et_couleurs() {
        assert!(couleur_severite("Critical").is_some());
        assert!(couleur_severite("High").is_some());
        assert!(couleur_severite("Red").is_some());
        assert!(couleur_severite("Green").is_some());
        assert!(couleur_severite("npx server").is_none());
    }

    #[test]
    fn tronquer_respecte_la_largeur() {
        let long = "a".repeat(200);
        let t = tronquer(&long, S_TABLE, 20.0);
        assert!(t.chars().count() < 60);
        assert!(t.ends_with('…'));
    }

    fn uuid_simple() -> u64 {
        // Pseudo-unique sans dépendance : adresse d'une pile locale.
        let x = 0u8;
        (&x as *const u8) as u64
    }
}
