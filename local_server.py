from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from backend import ApiMixin


class LocalHandler(ApiMixin, SimpleHTTPRequestHandler):
    """Serve the static UI and the same MongoDB API locally."""
    pass


def main():
    host = os.environ.get("DAYBOOK_HOST", "127.0.0.1")
    port = int(os.environ.get("DAYBOOK_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), LocalHandler)
    print(f"Daybook is running at http://{host}:{port}")
    print("Set MONGODB_URI to your Atlas connection string before creating an account.")
    print("Press Ctrl+C to stop the server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Daybook…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
