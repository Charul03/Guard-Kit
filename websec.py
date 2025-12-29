import requests

RECOMMENDED_HEADERS = [
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Strict-Transport-Security',
    'Referrer-Policy',
    'Permissions-Policy'
]

from models import Report, db

def save_report(title, category, type, content):
    report = Report(
        title=title,
        category=category,
        type=type,
        content=json.dumps(content, indent=2)
    )
    db.session.add(report)
    db.session.commit()

def check_security_headers(url: str, timeout: float = 6.0):
    """
    Fetch headers for the URL and show a user-friendly report of missing security headers.
    """
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = dict(r.headers)
        missing = [h for h in RECOMMENDED_HEADERS if h not in headers]

        # ---- User understandable formatted output ----
        print("\n🌐 Security Header Analysis Report")
        print("────────────────────────────────────────────")
        print(f"🔗 URL: {r.url}")
        print(f"📶 Status Code: {r.status_code}")
        print("────────────────────────────────────────────")
        print("🧩 Present Security Headers:")
        for h in RECOMMENDED_HEADERS:
            if h in headers:
                print(f"  ✅ {h}: Present")
            else:
                print(f"  ❌ {h}: Missing")
        print("────────────────────────────────────────────")

        if missing:
            print("⚠️  Missing Recommended Headers:")
            for h in missing:
                print(f"   - {h}")
            print("\n💡 Suggestion: Add the missing headers above for improved website security.")
        else:
            print("✅ All recommended security headers are present! Your website looks secure.")
        print("────────────────────────────────────────────\n")

        save_report(
            title=f"Header analysis: {url}",
            category="Web",
            type="dict",
            content=data
        )

        return {
            'url': r.url,
            'status_code': r.status_code,
            'headers': headers,
            'missing': missing
        }

    except Exception as e:
        print(f"❌ Error: Unable to check {url}\nReason: {str(e)}")
        return {'error': str(e)}
