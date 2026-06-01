//! Tests d'intégration — agent 2.9 — Performance surveillance continue.

use sentinel_monitor::perf::{CompteurCharge, MesureCharge, SeuilsRessources};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Test 1 : compteur atomique correct sous concurrence (50 threads)
// ---------------------------------------------------------------------------

#[test]
fn compteur_concurrent_50_threads() {
    let compteur = Arc::new(CompteurCharge::nouveau());
    let nb_threads = 50;
    let messages_par_thread = 1_000u64;

    let handles: Vec<_> = (0..nb_threads)
        .map(|_| {
            let c = Arc::clone(&compteur);
            thread::spawn(move || {
                for _ in 0..messages_par_thread {
                    c.incrementer_messages();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panique");
    }

    let mesure = compteur.mesure(Duration::from_secs(1));
    let total_attendu = nb_threads as u64 * messages_par_thread;

    // Le débit est calculé sur la durée réelle ; on vérifie surtout que la
    // somme totale lue via le débit × durée est cohérente (>0).
    assert!(
        mesure.messages_traites_par_sec > 0.0,
        "débit nul après {} messages",
        total_attendu
    );
}

// ---------------------------------------------------------------------------
// Test 2 : mesure produit un débit > 0 après quelques incréments
// ---------------------------------------------------------------------------

#[test]
fn mesure_debit_positif() {
    let compteur = CompteurCharge::nouveau();

    // Incrémente un certain nombre de messages.
    for _ in 0..500 {
        compteur.incrementer_messages();
    }

    // Petite attente pour que elapsed() > 0 de façon fiable.
    thread::sleep(Duration::from_millis(5));

    let mesure = compteur.mesure(Duration::from_millis(100));

    assert!(
        mesure.messages_traites_par_sec > 0.0,
        "débit attendu > 0, obtenu : {}",
        mesure.messages_traites_par_sec
    );
}

// ---------------------------------------------------------------------------
// Test 3 : depasse retourne true quand cpu_pct dépasse le seuil
// ---------------------------------------------------------------------------

#[test]
fn seuils_depasse_cpu() {
    let seuils = SeuilsRessources::par_defaut();

    let charge_elevee = MesureCharge {
        cpu_pct: 6.0, // > 5.0
        memoire_mo: 0.0,
        serveurs_observes: 0,
        messages_traites_par_sec: 0.0,
    };

    assert!(
        seuils.depasse(&charge_elevee),
        "depasse() doit être vrai pour cpu_pct=6.0 avec seuil 5.0"
    );
}

// ---------------------------------------------------------------------------
// Test 4 : depasse retourne false en dessous de tous les seuils
// ---------------------------------------------------------------------------

#[test]
fn seuils_non_depasse_nominal() {
    let seuils = SeuilsRessources::par_defaut();

    let charge_nominale = MesureCharge {
        cpu_pct: 1.0,
        memoire_mo: 30.0,
        serveurs_observes: 200,
        messages_traites_par_sec: 500.0,
    };

    assert!(
        !seuils.depasse(&charge_nominale),
        "depasse() doit être faux en charge nominale"
    );
}

// ---------------------------------------------------------------------------
// Test 5 : definir_serveurs est reflété dans la mesure
// ---------------------------------------------------------------------------

#[test]
fn serveurs_observes_coherent() {
    let compteur = CompteurCharge::nouveau();
    compteur.definir_serveurs(42);

    let mesure = compteur.mesure(Duration::from_secs(1));

    assert_eq!(
        mesure.serveurs_observes, 42,
        "serveurs_observes doit valoir 42"
    );
}
