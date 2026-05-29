import config
from webapp import create_app

app = create_app()

if __name__ == "__main__":
    ssl_context = None
    if getattr(config, "SSL_ENABLED", False):
        ssl_context = (config.SSL_CERT, config.SSL_KEY)

    app.run(
        host="0.0.0.0",
        port=getattr(config, "PORT", 5000),
        debug=False,
        threaded=True,
        ssl_context=ssl_context,
    )
