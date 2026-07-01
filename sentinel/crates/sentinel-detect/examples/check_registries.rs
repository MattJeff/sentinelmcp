//! Vérif réseau réelle des sources de registres vivantes.
//! `cargo run -p sentinel-detect --example check_registries`

#[tokio::main]
async fn main() {
    let connecteur = sentinel_detect::lookalikes::connecteur_par_defaut();
    println!("Sources actives : {}", connecteur.sources.len());
    let resultats = connecteur.interroger_tous().await;
    for (nom, res) in &resultats {
        match res {
            Ok(v) => {
                let exemples: Vec<&str> =
                    v.iter().take(3).map(|e| e.nom.as_str()).collect();
                println!("  {nom:<14} → {:>4} entrées  ex: {:?}", v.len(), exemples);
            }
            Err(e) => println!("  {nom:<14} → ERREUR: {e}"),
        }
    }
    let total = sentinel_detect::lookalikes::lister_tous_les_serveurs().await;
    println!("TOTAL dédupliqué : {} entrées", total.len());
}
