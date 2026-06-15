from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re

app = FastAPI(title="PrimeServe DLP Scanner")

class MessagePayload(BaseModel):
    message_text: str

# ১৬ ডিজিটের ক্রেডিট/ডেবিট কার্ড (PAN) এবং সাধারণ পাসওয়ার্ড প্যাটার্ন ডিটেকশনের জন্য Regex
PAN_PATTERN = r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
PASSWORD_PATTERN = r'(?i)(password|passwd|pin|secret)\s*[:=]\s*\S+'

@app.post("/api/v1/scan-message")
def scan_message(payload: MessagePayload):
    text = payload.message_text
    is_blocked = False
    flagged_reason = None
    
    # ১. কার্ড নম্বর চেক
    if re.search(PAN_PATTERN, text):
        is_blocked = True
        flagged_reason = "Sensitive Financial Data (Credit/Debit Card Number) detected."
        # ইচ্ছে করলে এখানে মাস্কিংও করতে পারেন: text = re.sub(PAN_PATTERN, "[CARD NUMBER MASKED]", text)
        
    # ২. পাসওয়ার্ড/পিন চেক
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
    uvicorn.run(app, host="127.0.0.1", port=8000)