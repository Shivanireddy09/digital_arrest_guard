"""
Digital Arrest / Impersonation Scam Analyzer
Rule-based scoring: each category has patterns + a weight.
Score is capped at 100 and mapped to LOW / MEDIUM / HIGH.
"""
import re
from lang_pack import EXTRA

CATEGORIES = {
    "Authority impersonation": {
        "weight": 20,
        "why": "Scammers pose as police, CBI, ED, NCB, TRAI, customs or courts. Real agencies do not handle cases over phone or WhatsApp calls.",
        "patterns": [
            r"\bcbi\b", r"\bcentral bureau\b", r"\bnarcotics\b", r"\bncb\b", r"\benforcement directorate\b",
            r"\bcyber ?crime (branch|cell|police)\b", r"\bcustoms?\b", r"\btrai\b", r"\bsupreme court\b",
            r"\bmumbai police\b", r"\bdelhi police\b", r"\bfedex\b", r"\bdhl\b", r"\bnarcotics bureau\b",
            r"\bofficer\b", r"\binspector\b", r"\bcrime branch\b", r"\bincome tax (dept|department|officer)\b",
        ],
    },
    "Accusation / fake case": {
        "weight": 20,
        "why": "A fake case (drugs in a parcel, money laundering, illegal ads, SIM misuse) is used to scare you.",
        "patterns": [
            r"\barrest(ed)?\b", r"\barrest warrant\b", r"\bwarrant\b", r"\bmoney laundering\b",
            r"\bdrugs?\b", r"\bpassports? (found|seized)\b", r"\bparcel\b", r"\bseized\b",
            r"\bfir\b", r"\bcase (has been )?(registered|filed)\b", r"\bsim card (misuse|blocked|illegal)\b",
            r"\baadhaar (is )?(linked|misused|used)\b", r"\billegal (activity|activities|transaction)\b",
            r"\bgiraftar\b", r"\bgirafthar\b",
        ],
    },
    "Threat / fear": {
        "weight": 15,
        "why": "Threats of jail, account freezing or family exposure are used to stop you from thinking.",
        "patterns": [
            r"\b(you will be|will be) (arrested|jailed|jailed|prosecuted)\b", r"\bjail\b", r"\bprison\b",
            r"\bblock(ed)? (your )?(sim|account|aadhaar|number)\b", r"\bfreeze(d)? (your )?(account|accounts)\b",
            r"\b(account|sim|number)s? (will be|is being|has been) (frozen|blocked|suspended|closed)\b",
            r"\blegal action\b", r"\bconsequences\b", r"\bserious (action|charges|trouble)\b", r"\bcriminal\b",
        ],
    },
    "Urgency / time pressure": {
        "weight": 10,
        "why": "Scammers rush victims so they cannot verify or talk to family.",
        "patterns": [
            r"\bimmediately\b", r"\bright now\b", r"\bwithin (\d+|one|two|few) (minutes?|hours?)\b",
            r"\burgent(ly)?\b", r"\blast (chance|warning)\b", r"\bdo not delay\b", r"\bno time\b",
        ],
    },
    "Secrecy / isolation": {
        "weight": 20,
        "why": "Telling you to keep it secret is the biggest red flag. It stops family and friends from stopping the scam.",
        "patterns": [
            r"\bdo(n'?t| not) (tell|inform|share with|discuss with) (anyone|anybody|family|your family)\b",
            r"\bkeep (this|it) (confidential|secret)\b", r"\bconfidential\b", r"\bsecret investigation\b",
            r"\bdo(n'?t| not) (hang up|disconnect|cut the call)\b", r"\bstay on (the )?(call|line|video)\b",
            r"\bkisi ko (mat|nahi) bata\w*\b", r"\bnational security\b",
        ],
    },
    "Video-call confinement": {
        "weight": 25,
        "why": "'Digital arrest' means being kept on a video call for hours. No real agency does this.",
        "patterns": [
            r"\bdigital(ly)? arrest\b", r"\bvideo call\b", r"\bskype\b", r"\bwhatsapp (video )?call\b",
            r"\bzoom\b", r"\bstay (in|on) (front of|the) (camera|video)\b", r"\bcamera (on|should be on)\b",
            r"\bhouse arrest\b", r"\bunder (surveillance|observation|investigation)\b", r"\bdo not leave\b",
        ],
    },
    "Money demand": {
        "weight": 30,
        "why": "Any demand to transfer money for 'verification', 'bail', 'fine' or a 'safe account' is a scam. Police and RBI never ask for this.",
        "patterns": [
            r"\bsafe (rbi )?account\b", r"\brbi (account|verification)\b", r"\bverification (amount|fee|account)\b",
            r"\btransfer\b", r"\bsend (the )?(money|amount|funds)\b", r"\bpay (a )?(fine|penalty|bail|fee)\b",
            r"\bbail (amount|money)\b", r"\bsecurity deposit\b", r"\b(upi|neft|rtgs|imps)\b",
            r"\bbank (details|account number|balance)\b", r"\bfixed deposit\b", r"\bsettle (the )?case\b",
            r"\bclearance (fee|amount|certificate)\b", r"\brs\.? ?\d[\d,]*\b", r"\b\u20b9 ?\d[\d,]*\b",
        ],
    },
    "Sensitive info request": {
        "weight": 15,
        "why": "Requests for Aadhaar, PAN, OTP, card or bank details are used for identity theft and account takeover.",
        "patterns": [
            r"\botp\b", r"\baadhaar (number|card|details)\b", r"\bpan (card|number)\b", r"\bcvv\b",
            r"\bcard (number|details)\b", r"\bnet ?banking\b", r"\bpassword\b", r"\bscreen ?shar(e|ing)\b",
            r"\bdownload\b.*\b(anydesk|teamviewer|app|apk)\b", r"\banydesk\b", r"\bteamviewer\b",
        ],
    },
    "Suspicious link": {
        "weight": 10,
        "why": "Shortened or unofficial links can lead to fake government pages or malware.",
        "patterns": [
            r"https?://\S+", r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly)/\S+",
            r"\bwww\.\S+", r"\b\S+\.apk\b",
        ],
    },
}

ADVICE = [
    "Do not send money, share OTP, Aadhaar, PAN or bank details. Real police, CBI or customs never ask for these on a call.",
    "There is no such thing as 'digital arrest' in Indian law. You cannot be arrested over a phone or video call.",
    "Hang up. Do not stay on the video call. Call the agency back on its official number or visit the local police station.",
    "Tell a family member or friend immediately. Scammers rely on secrecy.",
    "Report it on the national cybercrime helpline 1930 or at cybercrime.gov.in. If money was sent, report within minutes.",
    "Keep evidence: screenshots, phone numbers, UPI IDs and transaction details.",
]


def analyze(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        return {"score": 0, "level": "NONE", "findings": [], "advice": [], "message": "Please enter some text."}
    low = text.lower()
    findings, score = [], 0
    for name, cat in CATEGORIES.items():
        hits = []
        for pat in cat["patterns"]:
            for m in re.finditer(pat, low):
                hits.append(m.group(0))
        hits += [k for k in EXTRA.get(name, []) if k in low]  # Hindi / Telugu / Hinglish
        hits = sorted(set(hits))
        if hits:
            # more hits in a category adds a little, but never more than 1.5x of its weight
            pts = min(cat["weight"] * (1 + 0.15 * (len(hits) - 1)), cat["weight"] * 1.5)
            score += pts
            findings.append({"category": name, "matches": hits[:6], "why": cat["why"], "points": round(pts)})

    categories_hit = {f["category"] for f in findings}
    # combo bonuses: the classic digital arrest pattern
    if {"Authority impersonation", "Money demand"} <= categories_hit:
        score += 15
    if {"Video-call confinement", "Secrecy / isolation"} <= categories_hit:
        score += 15
    if {"Accusation / fake case", "Urgency / time pressure"} <= categories_hit:
        score += 10

    score = min(int(round(score)), 100)
    if len(categories_hit) < 2:
        score = min(score, 29)  # one signal alone (e.g. a bill amount) is not enough to alarm
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    findings.sort(key=lambda f: f["points"], reverse=True)
    return {
        "score": score,
        "level": level,
        "findings": findings,
        "advice": ADVICE if level in ("MEDIUM", "HIGH") else [
            "No strong scam signals found, but stay careful. If someone asks for money or secrecy, stop and verify independently."
        ],
        "message": "This is a risk indicator, not a final verdict.",
    }


if __name__ == "__main__":
    samples = [
        "This is CBI officer. A parcel in your name has drugs. You are under digital arrest. "
        "Stay on the video call, do not tell anyone, and transfer Rs 50,000 to the RBI safe account immediately.",
        "Hi, your Amazon order will be delivered tomorrow between 2 and 4 pm.",
    ]
    for s in samples:
        r = analyze(s)
        print(r["level"], r["score"], [f["category"] for f in r["findings"]])
