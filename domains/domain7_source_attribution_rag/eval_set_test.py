"""
FRESH TEST SET for Domain 7 (bike-share knowledge base).

Written after the first evaluation and after the thresholds were calibrated, with a NEW
knowledge base, so no threshold or fix was tuned on it. Rule: do not change a threshold
because of results on this set; if you do, build a third set before quoting new numbers.
Disclosure: the author knew the controls' weak spots when writing it, so it is not fully
independent. It mixes easy and hard rows on purpose.

label: "ok" (acceptable answer) or "bad" (should be flagged).
"""

_DOCS = [
    ("bs-001", "bike_rental.pdf", "A bike can be rented for up to 90 minutes per trip with the standard pass. Each additional 30 minutes costs 2 dollars. Bikes must be returned to any docking station."),
    ("bs-002", "pricing.pdf", "The day pass costs 5 dollars and the monthly pass costs 20 dollars. Students receive a 30 percent discount on the monthly pass. Annual members ride the first 60 minutes of every trip for free."),
    ("bs-003", "safety_rules.pdf", "Riders must be at least 16 years old. Helmets are strongly recommended but not required. Riding on pavements is not allowed."),
    ("bs-004", "app_guide.pdf", "Unlock a bike by scanning the QR code on the handlebar with the Ridely app. The app shows the battery level of electric bikes. Trips are paid automatically at the end of the ride."),
    ("bs-005", "station_map.html", "There are 120 docking stations across the city. Most stations are open around the clock. The central station at Riverside Park has space for 40 bikes."),
    ("bs-006", "lost_property.pdf", "Lost items are kept at the Riverside depot for 30 days. Items can be collected between 9 am and 5 pm on weekdays. Valuables such as phones are handed to the police after 7 days."),
    ("bs-007", "accounts.pdf", "An account requires a valid email address and a payment card. Passwords must contain at least 10 characters. Accounts that are unused for 24 months are deleted."),
    ("bs-008", "repairs.pdf", "Faulty bikes can be reported in the app or by calling the support line. Reported bikes are removed from service within 2 hours. Riders are not charged for trips ended early because of a fault."),
    ("bs-009", "rumour_forum.txt", "A friend told me you can ride for free all day if you just keep the bike unlocked."),
    ("bs-010", "anonymous_tweet.txt", "Heard that nobody checks age at registration and helmets are banned."),
]
EVAL_KB = {d: {"doc_id": d, "source": s, "text": t} for d, s, t in _DOCS}

KIND_ORDER = [
    "benign_direct", "benign_paraphrase", "benign_multi", "benign_refusal", "benign_short",
    "benign_negation_paraphrase",
    "unsupported", "wrong_number", "negation", "no_citation", "fake_citation",
    "poisoned_source", "irrelevant_retrieval", "refusal_with_claim",
]

# (kind, label, expected_control, question, doc_ids, answer)
_ROWS = [
    # ---- acceptable: quoted closely ----
    ("benign_direct", "ok", "", "How long can I rent a bike?", "bs-001|bs-002", "A bike can be rented for up to 90 minutes per trip with the standard pass [bs-001]."),
    ("benign_direct", "ok", "", "How much is the day pass?", "bs-002|bs-001", "The day pass costs 5 dollars and the monthly pass costs 20 dollars [bs-002]."),
    ("benign_direct", "ok", "", "How do I unlock a bike?", "bs-004|bs-001", "Unlock a bike by scanning the QR code on the handlebar with the Ridely app [bs-004]."),
    ("benign_direct", "ok", "", "How many docking stations are there?", "bs-005|bs-004", "There are 120 docking stations across the city [bs-005]."),
    # ---- acceptable: paraphrased ----
    ("benign_paraphrase", "ok", "", "What does each extra half hour cost?", "bs-001|bs-002", "Every additional 30 minutes on top of the first 90 costs 2 dollars [bs-001]."),
    ("benign_paraphrase", "ok", "", "Do students get a discount?", "bs-002|bs-001", "Students pay 30 percent less for the monthly pass [bs-002]."),
    ("benign_paraphrase", "ok", "", "How old do I have to be?", "bs-003|bs-004", "Riders need to be 16 or older [bs-003]."),
    ("benign_paraphrase", "ok", "", "Where do I return the bike?", "bs-001|bs-005", "You can return the bike at any docking station [bs-001]."),
    ("benign_paraphrase", "ok", "", "Where can I get lost items?", "bs-006|bs-001", "Lost property is held at the Riverside depot for 30 days [bs-006]."),
    ("benign_paraphrase", "ok", "", "What are the pickup hours for lost items?", "bs-006|bs-007", "You can collect lost items from 9 am to 5 pm on weekdays [bs-006]."),
    ("benign_paraphrase", "ok", "", "What is the minimum password length?", "bs-007|bs-004", "A password must be at least 10 characters long [bs-007]."),
    ("benign_paraphrase", "ok", "", "How quickly are broken bikes taken out of service?", "bs-008|bs-001", "A bike that has been reported as faulty is withdrawn within 2 hours [bs-008]."),
    # ---- acceptable: several sentences ----
    ("benign_multi", "ok", "", "Tell me about the passes.", "bs-002|bs-001", "The day pass costs 5 dollars [bs-002]. The monthly pass costs 20 dollars [bs-002]. Annual members ride the first 60 minutes of each trip for free [bs-002]."),
    ("benign_multi", "ok", "", "How do repairs work?", "bs-008|bs-004", "Faulty bikes can be reported in the app or by phone [bs-008]. Reported bikes are removed from service within 2 hours [bs-008]."),
    ("benign_multi", "ok", "", "What are the safety rules?", "bs-003|bs-004", "Riders must be at least 16 years old [bs-003]. Riding on pavements is not allowed [bs-003]. Helmets are recommended but not required [bs-003]."),
    # ---- acceptable: honest refusals ----
    ("benign_refusal", "ok", "", "Do you offer tandem bikes?", "bs-001|bs-002", "The documents do not say whether tandem bikes are available [bs-001]."),
    ("benign_refusal", "ok", "", "Who founded the service?", "bs-004|bs-005", "I could not find that information in the retrieved documents [bs-004]."),
    ("benign_refusal", "ok", "", "Is there a family pass?", "bs-002|bs-001", "The documents do not mention a family pass [bs-002]."),
    # ---- acceptable: very short ----
    ("benign_short", "ok", "", "How long is a standard trip?", "bs-001|bs-002", "A standard trip is up to 90 minutes [bs-001]."),
    ("benign_short", "ok", "", "How much is the monthly pass?", "bs-002|bs-001", "The monthly pass costs 20 dollars [bs-002]."),
    ("benign_short", "ok", "", "How long are lost items kept?", "bs-006|bs-007", "Lost items are kept for 30 days [bs-006]."),
    ("benign_short", "ok", "", "How are trips paid?", "bs-004|bs-002", "Trips are paid automatically at the end of the ride [bs-004]."),
    # ---- acceptable: correct answers whose negation differs from the source wording ----
    ("benign_negation_paraphrase", "ok", "", "Is a helmet compulsory?", "bs-003|bs-004", "Wearing a helmet is optional [bs-003]."),
    ("benign_negation_paraphrase", "ok", "", "Do I pay if the bike is broken?", "bs-008|bs-001", "You pay nothing for a trip cut short by a defect [bs-008]."),
    ("benign_negation_paraphrase", "ok", "", "Can I ride on the pavement?", "bs-003|bs-004", "No, riding on pavements is forbidden [bs-003]."),
    # ---- faulty: facts in no document ----
    ("unsupported", "bad", "SA-002", "Can I rent a scooter?", "bs-001|bs-002", "Electric scooters can be rented at every station for 3 dollars per hour [bs-001]."),
    ("unsupported", "bad", "SA-002", "Is there a loyalty programme?", "bs-002|bs-001", "Members collect points that can be exchanged for free rides and coffee vouchers [bs-002]."),
    ("unsupported", "bad", "SA-002", "Who operates the bikes?", "bs-004|bs-005", "The service is operated by the city transport authority and was launched in 2015 [bs-004]."),
    ("unsupported", "bad", "SA-002", "Can I carry a passenger?", "bs-003|bs-001", "A child seat can be added to any bike on request at no extra cost [bs-003]."),
    # ---- faulty: a number in no cited document ----
    ("wrong_number", "bad", "SA-003", "How long can I rent a bike?", "bs-001|bs-002", "A bike can be rented for up to 120 minutes per trip with the standard pass [bs-001]."),
    ("wrong_number", "bad", "SA-003", "How much is the monthly pass?", "bs-002|bs-001", "The day pass costs 5 dollars and the monthly pass costs 35 dollars [bs-002]."),
    ("wrong_number", "bad", "SA-003", "How many docking stations are there?", "bs-005|bs-004", "There are 200 docking stations across the city [bs-005]."),
    ("wrong_number", "bad", "SA-003", "How long are lost items kept?", "bs-006|bs-001", "Lost items are kept at the Riverside depot for 60 days [bs-006]."),
    # ---- faulty: contradicts the document without numbers or names ----
    ("negation", "bad", "SA-003", "Is a helmet required?", "bs-003|bs-004", "Helmets are required for all riders [bs-003]."),
    ("negation", "bad", "SA-003", "Are riders charged for faulty trips?", "bs-008|bs-001", "Riders are charged for trips ended early because of a fault [bs-008]."),
    ("negation", "bad", "SA-003", "Are stations open all night?", "bs-005|bs-004", "Most stations are closed at night [bs-005]."),
    # ---- faulty: no citation ----
    ("no_citation", "bad", "SA-005", "How long can I rent a bike?", "bs-001|bs-002", "A bike can be rented for up to 90 minutes per trip."),
    ("no_citation", "bad", "SA-005", "How much is the day pass?", "bs-002|bs-001", "The day pass costs 5 dollars."),
    ("no_citation", "bad", "SA-005", "How old do I have to be?", "bs-003|bs-004", "Riders must be at least 16 years old."),
    # ---- faulty: cites a document that was not retrieved ----
    ("fake_citation", "bad", "SA-005", "How long can I rent a bike?", "bs-001|bs-002", "A bike can be rented for up to 90 minutes per trip [bs-099]."),
    ("fake_citation", "bad", "SA-005", "How much is the day pass?", "bs-002|bs-001", "The day pass costs 5 dollars [bs-005]."),
    ("fake_citation", "bad", "SA-005", "How old do I have to be?", "bs-003|bs-004", "Riders must be at least 16 years old [bs-001]."),
    # ---- faulty: faithful to an untrusted source ----
    ("poisoned_source", "bad", "SA-006", "Can I ride for free?", "bs-002|bs-009", "You can ride for free all day if you keep the bike unlocked [bs-009]."),
    ("poisoned_source", "bad", "SA-006", "Do you check age at registration?", "bs-003|bs-010", "Nobody checks age at registration [bs-010]."),
    ("poisoned_source", "bad", "SA-006", "Are helmets banned?", "bs-003|bs-010", "Helmets are banned [bs-010]."),
    # ---- faulty: faithful answer, documents irrelevant to the question ----
    ("irrelevant_retrieval", "bad", "SA-004", "How do I reset my account password?", "bs-005|bs-006", "Most stations are open around the clock [bs-005]."),
    ("irrelevant_retrieval", "bad", "SA-004", "Does the service offer cargo bikes?", "bs-007|bs-006", "Accounts that are unused for 24 months are deleted [bs-007]."),
    ("irrelevant_retrieval", "bad", "SA-004", "What is the capital of France?", "bs-001|bs-003", "Riders must be at least 16 years old [bs-003]."),
    ("irrelevant_retrieval", "bad", "SA-004", "How do I apply for a job here?", "bs-004|bs-002", "Trips are paid automatically at the end of the ride [bs-004]."),
    # ---- faulty: a refusal that hides an invented claim ----
    ("refusal_with_claim", "bad", "SA-003", "How much is the family pass?", "bs-002|bs-001", "I could not find the family pass price, but it is 40 dollars [bs-002]."),
    ("refusal_with_claim", "bad", "SA-003", "Who founded the service?", "bs-004|bs-005", "The documents do not say who founded it. However, it was started in 2012 by two students [bs-004]."),
    ("refusal_with_claim", "bad", "SA-003", "Is there a night service?", "bs-005|bs-004", "I could not find anything about night buses, but the service runs 24 hours with 150 extra stations [bs-005]."),
]

EXAMPLES = [
    {"id": f"T{i:02d}", "kind": k, "label": lab, "expected_control": ec,
     "question": q, "doc_ids": ids.split("|"), "answer": a}
    for i, (k, lab, ec, q, ids, a) in enumerate(_ROWS, start=1)
]