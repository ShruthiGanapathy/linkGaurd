from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
import validators
app = Flask(__name__)

def is_valid_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme in ['http', 'https'] and parsed_url.netloc:
        return True
    return False

def check_Url(url):
    reasons=[]
    score=0

    sus_keywords=["login", "verify", "update", "free", "winner", "claim", "password"]
    for keyword in sus_keywords:
        if keyword in url.lower():
            reasons.append(f"suspicious keyword {keyword}")
            score+=20
    
    if re.match(r"http[s]?://\d{1,3}(\.\d{1,3}){3}",url):
        reasons.append("Using IP address")
        score+=30

    if "bit.ly" in url or "tinyurl" in url:
        reasons.append("Shortenned url")
        score+=25

    verdict="Safe"
    if score>=75:
        verdict = "Dangerous"
    elif score>=50:
        verdict = "Suspicious"
    
    return {"score":score, "verdict":verdict, "reasons":reasons}

@app.route("/",methods=['GET','POST'])
def index():
    result = None
    details = None
    verdict_only = None
    if request.method == 'POST':    #Did the user press the submit button? If yes, then let’s process the form
        url = request.form.get("url").strip()  #gets the data from form and pulls input url 
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "https://" + url
            parsed_url = urlparse(url)

        if not validators.url(url):
            result = "Invalid URL"
        else:
            analyze = check_Url(url)

            if not analyze or not isinstance(analyze, dict):
                result = "Couldn't analyze this URL. Please try a different one."
            else:
                verdict_only = analyze.get("verdict", "Unknown")
                #score = analyze.get("score", "N/A")
                result = f"Verdict: {verdict_only}"
                details = analyze.get("reasons") or []
                # if not details:
                #     details=[]
    return render_template("index.html",result=result,details=details,verdict=verdict_only)

if __name__ == '__main__':
    app.run(debug=True)