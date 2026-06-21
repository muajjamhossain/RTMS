from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re

app = FastAPI(title="PrimeServe DLP Scanner")

class MessagePayload(BaseModel):
    message_text: str

# ১৬ ডিজিটের ক্রেডিট/ডেবিট কার্ড (PAN) এবং সাধারণ পাসওয়ার্ড প্যাটার্ন ডিটেকশনের জন্য Regex
PAN_PATTERN = r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
PASSWORD_PATTERN = r'(?i)(password|passwd|pin|secret)\s*[:=]\s*\S+'

def verify_luhn(card_number: str) -> bool:
    """
    Luhn Algorithm (Mod 10) চেক করার হেল্পার ফাংশন।
    কার্ড নম্বরটি বৈধ হলে True, অন্যথায় False রিটার্ন করবে।
    """
    # শুধু সংখ্যাগুলো আলাদা করে নিচ্ছি (স্পেস বা হাইফেন বাদ দিয়ে)
    digits = [int(d) for d in card_number if d.isdigit()]
    
    # ডান দিক থেকে প্রতি ২য় ডিজিটকে দ্বিগুণ করা
    for i in range(len(digits) - 2, -1, -2):
        double_val = digits[i] * 2
        # গুণফল ৯ এর বড় হলে ডিজিট দুটি যোগ করা (যেমন: ১৪ -> ১+৪ = ৫, যা ১৪-৯ এর সমান)
        if double_val > 9:
            double_val -= 9
        digits[i] = double_val
        
    # সর্বমোট যোগফল ১০ দিয়ে বিভাজ্য কিনা তা যাচাই করা
    return sum(digits) % 10 == 0

@app.post("/api/v1/scan-message")
def scan_message(payload: MessagePayload):
    text = payload.message_text
    is_blocked = False
    flagged_reason = None
    
    # ১. কার্ড নম্বর চেক (Regex + Luhn/Mod 10)
    found_cards = re.findall(PAN_PATTERN, text)
    valid_card_detected = False
    
    for card in found_cards:
        if verify_luhn(card):
            valid_card_detected = True
            break  # একটি ভ্যালিড কার্ড পাওয়াই ব্লক করার জন্য যথেষ্ট
            
    if valid_card_detected:
        is_blocked = True
        flagged_reason = "Sensitive Financial Data (Valid Credit/Debit Card Number) detected."
        # ইচ্ছে করলে এখানে মাস্কিংও করতে পারেন: text = re.sub(PAN_PATTERN, "[CARD NUMBER MASKED]", text)
        
    # ২. পাসওয়ার্ড/পিন চেক (যদি কার্ড না পাওয়া যায়)
    elif re.search(PASSWORD_PATTERN, text):
        is_blocked = True
        flagged_reason = "Security Risk: System Password or PIN exposure detected."

    return {
        "status": "success",
        "is_blocked": is_blocked,
        "flagged_reason": flagged_reason,
        "processed_text": text
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.5", port=5000)