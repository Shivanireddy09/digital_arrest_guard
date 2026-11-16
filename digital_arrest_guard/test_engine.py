# -*- coding: utf-8 -*-
"""Run: python test_engine.py   -> prints a result table and accuracy numbers for your report."""
from scam_engine import analyze

# (language, text, is_scam)
CASES = [
    # ---------- SCAM: English ----------
    ("EN", "This is CBI officer. A parcel in your name has drugs. You are under digital arrest. Stay on video call, do not tell anyone, transfer Rs 50,000 to RBI safe account immediately.", True),
    ("EN", "Mumbai Police cyber crime branch here. Your Aadhaar is linked to money laundering. An arrest warrant is issued. Do not disconnect the call.", True),
    ("EN", "Customs department: your FedEx parcel has passports and illegal items. Pay a fine of Rs 30000 via UPI or you will be arrested.", True),
    ("EN", "TRAI notice: your SIM will be blocked within 2 hours for illegal activity. Press 9 to talk to officer. Keep this confidential.", True),
    ("EN", "Supreme court order against you. Join Skype video call now and share your bank details for verification. Do not tell your family.", True),
    ("EN", "Narcotics bureau has seized a parcel with your Aadhaar. Pay security deposit to settle the case or face jail.", True),
    # ---------- SCAM: Hindi ----------
    ("HI", "यह CBI अधिकारी बोल रहा हूँ। आपके पार्सल में ड्रग्स मिले हैं। आप डिजिटल अरेस्ट में हैं। किसी को मत बताना और तुरंत पैसे ट्रांसफर करें।", True),
    ("HI", "मुंबई पुलिस साइबर क्राइम से बोल रहे हैं। आपके आधार पर मनी लॉन्ड्रिंग का केस है। गिरफ्तार वारंट जारी है। कॉल न काटें।", True),
    ("HI", "आपका सिम बंद होने वाला है। अपना OTP और आधार नंबर बताइए, वरना खाता फ्रीज कर दिया जाएगा।", True),
    # ---------- SCAM: Telugu ----------
    ("TE", "ఇది CBI అధికారి. మీ పార్సిల్‌లో డ్రగ్స్ దొరికాయి. మీరు డిజిటల్ అరెస్ట్‌లో ఉన్నారు. ఎవరికీ చెప్పవద్దు, వెంటనే డబ్బు ట్రాన్స్ఫర్ చేయండి.", True),
    ("TE", "కస్టమ్స్ అధికారి మాట్లాడుతున్నాను. మీ పేరుతో అరెస్ట్ వారెంట్ ఉంది. వీడియో కాల్‌లో ఉండండి, కాల్ కట్ చేయవద్దు. జరిమానా చెల్లించండి.", True),
    # ---------- SCAM: Hinglish / Tenglish ----------
    ("HINGLISH", "Aapke naam pe parcel mein drugs mile hain. Aap digital arrest mein ho. Kisi ko mat batana, turant paise transfer karo.", True),
    ("TENGLISH", "Mee parcel lo drugs dorikayi. Digital arrest lo unnaru. Evariki cheppakandi, ventane dabbulu pampandi.", True),
    # ---------- SCAM: subtle / short ----------
    ("EN", "Police here. Verify your identity on this link http://bit.ly/verify-case immediately or your account will be frozen.", True),
    ("EN", "ED officer calling. You are being investigated. Share OTP and do not tell anyone about this call.", True),
    # ---------- LEGIT ----------
    ("EN", "Your Amazon order will be delivered tomorrow between 2 and 4 pm.", False),
    ("EN", "Hi mom, I will call you in the evening. Please keep the video call link ready for Sunday.", False),
    ("EN", "Reminder: your electricity bill of Rs 1,250 is due on 20th. Pay on the official app.", False),
    ("EN", "Team meeting is shifted to 3 pm today. Join using the Zoom link shared in the calendar invite.", False),
    ("EN", "Your OTP for login is 482913. Do not share it with anyone. Valid for 5 minutes.", False),
    ("EN", "Traffic police have started a drive on helmets this week. Please wear a helmet and ride safe.", False),
    ("EN", "The customs office will be closed on Saturday for the festival holiday.", False),
    ("EN", "Congratulations, your exam result is out. Check it on the college website.", False),
    ("HI", "आपका बिजली का बिल 20 तारीख तक जमा करना है। कृपया आधिकारिक ऐप से भुगतान करें।", False),
    ("HI", "माँ, मैं शाम को फोन करूँगा। रविवार को वीडियो कॉल पर बात करेंगे।", False),
    ("HI", "आपका ऑर्डर कल शाम तक डिलीवर हो जाएगा। धन्यवाद।", False),
    ("TE", "మీ కరెంట్ బిల్లు 20వ తేదీలోపు చెల్లించాలి. దయచేసి అధికారిక యాప్ ద్వారా చెల్లించండి.", False),
    ("TE", "అమ్మా, సాయంత్రం ఫోన్ చేస్తాను. ఆదివారం వీడియో కాల్‌లో మాట్లాడుకుందాం.", False),
    ("TE", "మీ ఆర్డర్ రేపు సాయంత్రంలోగా డెలివరీ అవుతుంది. ధన్యవాదాలు.", False),
    ("EN", "Bank notice: your statement for October is ready. Login to the official website to download it.", False),
    ("EN", "Cyber awareness week: learn how to spot fake CBI and police calls. Never share OTP.", False),
]


def run():
    tp = tn = fp = fn = 0
    print(f"{'#':>2} {'Lang':8} {'Expected':8} {'Got':7} {'Score':>5}  Result   Text")
    print("-" * 100)
    for i, (lang, text, is_scam) in enumerate(CASES, 1):
        r = analyze(text)
        flagged = r["level"] in ("MEDIUM", "HIGH")
        ok = flagged == is_scam
        if is_scam and flagged: tp += 1
        elif is_scam and not flagged: fn += 1
        elif not is_scam and flagged: fp += 1
        else: tn += 1
        print(f"{i:>2} {lang:8} {'SCAM' if is_scam else 'SAFE':8} {r['level']:7} {r['score']:>5}  {'OK ' if ok else 'MISS'}     {text[:48]}")
    total = len(CASES)
    acc = (tp + tn) / total * 100
    prec = tp / (tp + fp) * 100 if tp + fp else 0
    rec = tp / (tp + fn) * 100 if tp + fn else 0
    print("-" * 100)
    print(f"Total={total}  TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print(f"Accuracy={acc:.1f}%  Precision={prec:.1f}%  Recall={rec:.1f}%")


if __name__ == "__main__":
    run()
