"""The feature contract shared by every part of the project (Section 7 of the brief).

Changing this list changes the model input dimension, so change it only with the
whole team and retrain. Missing features are None, never dropped.
"""

# Ordered feature list. Order matters: it is the column order of the model input.
FEATURES = [
    # Volume (all nodes)
    "paquets_s", "octets_s", "requetes_s", "nb_flux",
    # Connections (all nodes)
    "connexions_ouvertes", "ratio_syn", "duree_moy_connexion",
    # Diversity (all nodes)
    "nb_sources_uniques", "nb_destinations", "nb_ports", "entropie_url", "entropie_ua",
    # Regularity (external sources; None on internal nodes)
    "variabilite_intervalles", "taille_moy_paquets",
    # Health (internal components; None on external nodes)
    "cpu", "memoire", "latence_p95", "taux_erreurs",
    # Alerts (all nodes)
    "nb_alertes", "gravite_max_alerte",
    # Context (all nodes)
    "instant_premiere_anomalie",
]

NODE_TYPES = ["externe", "gateway", "service", "database", "cache", "pod", "k8s_node"]
VERDICTS = ["normal", "pic_legitime", "attaque"]
ATTACK_TYPES = [
    "none", "ddos_udp_flood", "ddos_icmp_flood", "ddos_syn_flood", "ddos_http_flood",
    "slowloris", "slow_post", "bruteforce_distribue", "scan_distribue",
]

# Which features are meaningful on which role, for the "feature present" flags and
# for not confusing "missing" with "zero".
EXTERNAL_ONLY = {"variabilite_intervalles", "taille_moy_paquets"}
INTERNAL_ONLY = {"cpu", "memoire", "latence_p95", "taux_erreurs"}

WINDOW_S = 10.0
STEP_S = 5.0
