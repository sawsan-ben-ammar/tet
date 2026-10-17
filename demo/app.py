"""Streamlit dashboard (Phase 8): inspect graph windows, GNN predictions,
incidents and evaluation metrics — for both the synthetic demo and the real lab
captures.

    streamlit run demo/app.py
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st  # noqa: E402

from data_prep.synth import make_window  # noqa: E402
from data_prep.to_graph import window_to_data  # noqa: E402
from data_prep.dataset import load_dir  # noqa: E402
from model.correlation import load_model  # noqa: E402
from model.predict import predict_window  # noqa: E402
from model.explain import build_explanation, top_attention_edges  # noqa: E402
from schema.features import ATTACK_TYPES  # noqa: E402

st.set_page_config(page_title="Correlation d'attaques distribuees (GNN)", layout="wide")


@st.cache_resource
def _model(artifacts):
    return load_model(artifacts)


def _synth_scenario(kind, atype, n, seed):
    import datetime as dt
    base = dt.datetime(2026, 1, 1)
    plan = [("normal", "none")] * 3 + [(kind, atype)] * n + [("normal", "none")] * 2
    return [make_window(v, a, scenario="demo",
                        debut=(base + dt.timedelta(seconds=5 * i)).isoformat() + "Z", seed=seed + i)
            for i, (v, a) in enumerate(plan)]


st.title("Correlation topologique d'attaques distribuees — GNN")

with st.sidebar:
    st.header("Source")
    mode = st.radio("Donnees", ["Captures reelles (labo)", "Demo synthetique"])
    # real captures -> real-trained model; synthetic demo -> synthetic-trained model
    _art = "model/artifacts" if mode.startswith("Captures") else "model/artifacts_synth"
    if not os.path.exists(os.path.join(_art, "model.pt")):
        _art = "model/artifacts"
model, stats = _model(_art)

with st.sidebar:
    if mode.startswith("Captures"):
        caps = sorted(glob.glob("data/windows/real-*"))
        cap = st.selectbox("Capture", [os.path.basename(c) for c in caps] or ["(aucune)"])
        wins = load_dir(os.path.join("data/windows", cap)) if caps else []
    else:
        kind = st.selectbox("Situation", ["attaque", "pic_legitime", "normal"])
        atype = st.selectbox("Type", [a for a in ATTACK_TYPES if a != "none"],
                             disabled=(kind != "attaque"))
        seed = st.number_input("Graine", 0, 9999, 42)
        wins = _synth_scenario(kind, atype if kind == "attaque" else "none", 6, int(seed))
    idx = st.slider("Fenetre", 0, max(len(wins) - 1, 0), min(3, max(len(wins) - 1, 0))) if wins else 0

if not wins:
    st.warning("Aucune fenetre a afficher. Lancez une capture (lab/scenario_runner.py) et "
               "python -m collect.run_capture.")
    st.stop()

w = wins[idx]
data = window_to_data(w, stats)
res, out = predict_window(model, data)

c1, c2, c3 = st.columns(3)
color = {"attaque": "red", "pic_legitime": "orange", "normal": "green"}[res["verdict"]]
c1.markdown(f"### Verdict : :{color}[{res['verdict']}]")
c1.metric("Confiance", f"{res['confiance']:.2f}")
c1.metric("P(attaque)", f"{res.get('p_attack', 0):.2f}")
c2.markdown(f"**Type predit** : {res['type']}")
c2.markdown(f"**Verite terrain** : {w['labels']['verdict']} / {w['labels']['type']}")
c2.markdown(f"**Fenetre** : {w['fenetre']['debut']}")
cibles = res["cibles"] if isinstance(res["cibles"], dict) else {}
c3.markdown(f"**Cibles (predit)** : {', '.join(list(cibles)[:3]) or '-'}")
c3.markdown(f"**Cibles (verite)** : {', '.join(w['labels'].get('cibles', [])) or '-'}")
c3.markdown(f"**Noeuds / aretes** : {len(w['noeuds'])} / {len(w['aretes'])}")

if res["verdict"] == "attaque":
    st.subheader("Sources attaquantes (indicateurs, non attribution)")
    src = res["sources"] if isinstance(res["sources"], dict) else {}
    st.dataframe([{"sous_reseau": k, "score": round(v, 3)} for k, v in
                  sorted(src.items(), key=lambda kv: -kv[1])][:15], use_container_width=True)
    st.info(build_explanation(w, res, data, out))
    with st.expander("Flux les plus attentionnes (GAT)"):
        st.table(top_attention_edges(data, out, k=8))

st.subheader("Timeline du scenario (predit vs verite)")
rows = []
for i, ww in enumerate(wins):
    r, _ = predict_window(model, window_to_data(ww, stats))
    rows.append({"fenetre": i, "debut": ww["fenetre"]["debut"][11:19],
                 "predit": r["verdict"], "verite": ww["labels"]["verdict"],
                 "p_attaque": round(r.get("p_attack", 0), 2)})
st.dataframe(rows, use_container_width=True, height=240)

# incidents for this capture (Phase 7), if present
if mode.startswith("Captures"):
    incp = os.path.join("data/captures", cap, "incidents.json")
    if os.path.exists(incp):
        st.subheader("Incidents correles (Phase 7)")
        inc = json.load(open(incp))
        st.caption(f"{inc.get('n_incidents', 0)} incident(s), "
                   f"{inc.get('n_attack_windows', 0)} fenetres d'attaque")
        for it in inc.get("incidents", []):
            with st.expander(f"{it['incident_id']} — {it['categorie_predite']} "
                             f"(conf {it['confiance']}) {it['debut']}..{it['fin']}"):
                st.write("**Faits observes**", it["faits_observes"])
                st.write("**Cibles inferees**", it["cibles_inferees"])
                st.write("**Sources inferees (indicateurs)**", it["sources_inferees"][:10])
                st.write("**Capteurs**", it["capteurs_disponibles"])
                st.write("**Limites de preuve**", it["limites_preuve"])
                st.write("**Etapes recommandees**", it["etapes_recommandees"])

# evaluation metrics (Phase 6), if present
rep = "reports/phase6/phase6.json"
if os.path.exists(rep):
    st.subheader("Evaluation (Phase 6)")
    data6 = json.load(open(rep))
    for key in ("real", "synth"):
        if key in data6:
            st.markdown(f"**{data6[key]['name']}** — {data6[key]['n_windows']} fenetres, "
                        f"split {data6[key]['split']}")
            st.code(data6[key]["table"])
