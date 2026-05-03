"""vendor_audit.web — public web-service layer.

This is a separate, optional subpackage. The CLI does not import it. To run
the web service, install the optional 'web' extra:

    pip install -e '.[web]'

Then start with:

    uvicorn vendor_audit.web.app:app --host 127.0.0.1 --port 8000

The web layer binds to 127.0.0.1 only; it is meant to sit behind cloudflared
(or a similar tunnel) which terminates TLS and provides the public path.
"""
