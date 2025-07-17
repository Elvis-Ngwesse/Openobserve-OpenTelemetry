import logging
import tracing  # your tracing setup module
from flask import Flask
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry import trace
import sys

# Setup basic logging to stdout with debug level
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s:%(name)s:%(message)s",
)
logger = logging.getLogger(__name__)

# Get a tracer instance
tracer = trace.get_tracer(__name__)

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

@app.route("/")
def hello():
    logger.info("Received request to /")
    with tracer.start_as_current_span("hello-span"):
        logger.info("Inside traced span for /")
        return 'Hello World!'

if __name__ == "__main__":
    logger.info("Starting Flask app on port 5011")
    # Bind to 0.0.0.0 for Docker and disable reloader
    app.run(debug=True, port=5011, host="0.0.0.0", use_reloader=False)
